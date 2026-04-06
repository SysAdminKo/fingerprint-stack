# Fingerprint stack (H2 Edge + upstream + net agents)

Этот репозиторий/рабочая директория описывает стенд, который собирает и отображает максимум информации о fingerprint клиента при заходе на:

- `https://kf58p1vqbctehrki.mooo.com`

Цель: приблизиться по набору данных/выводу к `tls.peet.ws`, но на своей машине.

---

## Что сделано

### 1) Публичный HTTPS сайт

- **Домен**: `kf58p1vqbctehrki.mooo.com`
- **TLS сертификат**: Let’s Encrypt (certbot; файлы в `/etc/letsencrypt/live/...`).
- **HTTP/3 отключён**: используется только **h1/h2**.

Сертификаты обновляются через `certbot-renew.timer` с короткой остановкой `fp-h2edge` (standalone HTTP-01), потому что `fp-h2edge` занимает `:80/:443`, и для ACME-челленджа certbot на время поднимает свой временный listener на `:80`.

```bash
systemctl status certbot-renew.timer
sudo certbot renew --dry-run --no-random-sleep-on-renew
```

### 2) HTTP/2 Edge (frame-level fingerprint) — основной вход

Это сервис `fp-h2edge`, который занимает **:443 и :80** и является **первым HTTP/2 endpoint**. Поэтому он может собирать **frame-level HTTP/2 fingerprint** (preface/SETTINGS/WINDOW_UPDATE/PRIORITY).

Также `fp-h2edge` дополнительно собирает на TLS-уровне:

- **JA3/JA4** (из plaintext ClientHello до TLS handshake)
- **ClientHello tables** (cipher suites/extensions/curves/ALPN/supported_versions)
- **HTTP fingerprint (approx)**: хэш от HTTP заголовков + списка header names
- **TLS handshake dumps (best-effort)**:
  - raw TLS record с **ClientHello** (base64)
  - raw TLS records, которые сервер отправил во время handshake (base64)
  - best-effort парсинг **ServerHello** (TLS 1.3 после ServerHello идёт шифрованный handshake)

И дальше проксирует запросы в upstream `http://127.0.0.1:9000`, передавая всё через заголовки:

- `X-H2-*` (frame-level данные)
- `X-TLS-*` (agreed TLS)
- `X-CH-*` (ClientHello lists)
- `X-JA4`, `JA3`, `X-HTTP-FP`
- `X-TLS-ClientHello-Record-B64`, `X-TLS-ServerHandshake-Records-B64`, `X-TLS-ServerHello-JSON`

### 3) Upstream (UI/API)

Локальный сервис (`fp-upstream`) на `127.0.0.1:9000`:

- Рисует HTML страницу со структурированными секциями.
- Отдаёт JSON API:
  - `/api/all` — всё, что собрано
  - `/api/clean` — “короткая” сводка fingerprints + TLS + ClientHello
  - `/api/tls` — TLS/ClientHello блок
  - `/api/tcp` — p0f (TCP/IP stack fingerprint)
  - `/api/ttl` — TTL (eBPF)
  - `/api/handshake` — дампы TLS ClientHello/ServerHello (base64 + parsed summary)
  - `/api/pcap` — выгрузка `.pcap` “на лету” (server-side `tcpdump`, короткое окно, legacy)
  - `/api/pcap/start` — старт capture в фоне (под UI-кнопку)
  - `/api/pcap/result` — получение результата capture (ZIP)
  - `/readme` — отображение `README.md` (рендер Markdown → HTML)

**Важно про “Proto” в UI:** upstream (`fp-upstream`) видит входящее соединение **от reverse-proxy** (edge → `127.0.0.1:9000`), и это соединение обычно **HTTP/1.1**. При этом внешний клиент (браузер) может приходить на edge по **HTTP/2**.

Чтобы не путаться, UI upstream показывает:

- **Proto (client)** — протокол внешнего запроса (как пришёл клиент на edge)
- **Proto (upstream)** — протокол запроса между edge и upstream (как видит upstream)
- **ALPN (client)** — согласованный ALPN на внешнем TLS (обычно `h2`)

Для этого edge дополнительно пробрасывает заголовки:

- `X-Client-Proto` — внешний HTTP proto (например, `HTTP/2.0`)
- `X-Client-ALPN` — внешний ALPN (например, `h2`)

`/api/pcap` запускает `tcpdump` на сервере и возвращает файл как download (legacy):

- `GET /api/pcap?dur_s=3` — снять трафик для текущего `client_ip` на \(3\) секунды (значение ограничено \(1..10\))
- `GET /api/pcap?ip=<ip>&dur_s=3` — снять трафик для указанного IP (если нужно снять рукопожатие “не для текущего запроса”)

Примечание про рукопожатие: чтобы в `.pcap` попал **TLS handshake**, в окне capture должен произойти **новый TCP/TLS коннект**. Обычный вызов `/api/pcap` стартует `tcpdump` уже после обработки запроса, поэтому часто видны только “пост-рукопожатные” пакеты.

Для удобства в UI есть кнопка **Capture `.pcap`**, которая делает:

1) `GET /api/pcap/start?dur_s=<n>` — запускает `tcpdump` **в фоне** и возвращает `token`
2) навигация на `GET /__close?next=/?pcap_token=<token>` на edge:
   - edge отдаёт небольшой HTML с client-side redirect на `next`
   - затем edge закрывает текущий HTTP/2 коннект (чтобы следующий запрос открыл новый TCP/TLS session)
3) загрузка страницы `/?pcap_token=<token>` (новый TCP/TLS коннект попадает в окно capture)
4) во время capture UI дополнительно дёргает `/ws` (best-effort), чтобы WebSocket-handshake трафик попал в `.pcap`
5) polling `GET /api/pcap/result?probe=1&token=<token>` (пока capture идёт — `202`)
6) скачивание **ZIP** через iframe: `GET /api/pcap/result?token=<token>` (attachment download), затем auto-reload

Переменные окружения upstream:

- `FP_PCAP_IFACE` — интерфейс для `tcpdump` (по умолчанию `any`)
- `FP_PCAP_TCPDUMP` — путь до `tcpdump` (по умолчанию `/usr/sbin/tcpdump`)
- `FP_PCAP_SAVE_DIR` — директория, куда **сохраняются** все `.pcap` и рядом снапшот `/api/all` (по умолчанию `/var/lib/fp/pcap`)
- `FP_PCAP_DIR` — директория для временных `.pcap` (legacy `/api/pcap`, по умолчанию `/tmp/fp-pcaps`)

Формат сохранения:

- `.pcap`: `handshake-<UTC>-<ip>-<token>.pcap`
- рядом снапшот `/api/all`: `handshake-<UTC>-<ip>-<token>-api-all.json`
- при скачивании через `/api/pcap/result` отдаётся ZIP: `handshake-<UTC>-<ip>-<token>.zip` с двумя файлами выше внутри

### 5) TCP/IP stack fingerprint (p0f)

Поднят `p0f` как системный сервис и слушает unix socket:

- `/var/run/p0f.sock`

Upstream по `client_ip` (берётся из `X-Forwarded-For`) делает запрос в `p0f-client` и отображает/возвращает результат.

### 6) TTL (eBPF/BCC)

Поднят `fp-netagent` — Python + BCC eBPF-агент:

- цепляется kprobe к `ip_rcv`
- сохраняет TTL входящих IPv4 пакетов по `source ip`
- отдаёт данные локально по HTTP:
  - `http://127.0.0.1:9100/api/ttl/all`
  - `http://127.0.0.1:9100/api/ttl/ip/<ip>`

Upstream дергает этот агент и показывает TTL на странице + отдаёт через `/api/ttl`.

---

## Архитектура / Поток данных (текущий вариант B)

1) Клиент приходит на `kf58p1vqbctehrki.mooo.com:443`
2) `fp-h2edge` принимает TCP/TLS:
   - читает первый TLS record (ClientHello) и вычисляет **JA3/JA4** + парсит списки (cipher suites/extensions/curves/ALPN/supported_versions)
   - сохраняет дамп ClientHello record (base64) и best-effort вытаскивает ServerHello из outbound handshake records
   - выполняет TLS handshake
3) `fp-h2edge` принимает HTTP/2:
   - читает client preface и первые фреймы (SETTINGS/WINDOW_UPDATE/PRIORITY/HEADERS)
   - считает **frame-level H2 fingerprint** и сохраняет его
4) `fp-h2edge` проксирует запрос в upstream `127.0.0.1:9000`, добавляя заголовки:
   - `X-H2-FP`, `X-H2-Settings`, `X-H2-Window-Incr`, `X-H2-Priority-Frames`
   - `X-TLS-*`, `X-CH-*`, `X-JA4`, `JA3`, `X-HTTP-FP`
   - `X-TLS-ClientHello-Record-B64`, `X-TLS-ServerHandshake-Records-B64`, `X-TLS-ServerHello-JSON`
5) Upstream агрегирует:
   - из заголовков выше
   - из `p0f` (TCP/IP stack)
   - из `fp-netagent` (TTL)
6) Upstream отдаёт HTML + JSON API

---

## Где что находится (пути на этой машине)

### Конфиги

- **Let's Encrypt (certbot)**:
  - `/etc/letsencrypt/live/kf58p1vqbctehrki.mooo.com/fullchain.pem`
  - `/etc/letsencrypt/live/kf58p1vqbctehrki.mooo.com/privkey.pem`
  - hooks: `/etc/letsencrypt/renewal-hooks/{pre,post,deploy}/`
- **systemd unit H2 edge**: `/etc/systemd/system/fp-h2edge.service`
- **systemd unit upstream**: `/etc/systemd/system/fp-upstream.service`
- **systemd unit p0f**: `/etc/systemd/system/p0f.service`
- **systemd unit TTL agent**: `/etc/systemd/system/fp-netagent.service`

### Бинарники / скрипты

- **H2 edge**: `/usr/local/bin/fp-h2edge`
- **Upstream**: `/usr/local/bin/fp-upstream`
- **TTL agent**: `/usr/local/bin/fp-netagent`
- **p0f**: `/usr/sbin/p0f`, `/usr/sbin/p0f-client`

### Исходники (в этой домашней директории)

> Эти пути важны, чтобы в будущих чатах быстро находить код сервисов.

- **H2 edge (frame-level)**: `/home/drzbodun/fp/h2edge/`
- **Upstream сервис**: `/home/drzbodun/fp/upstream/`
- **TTL netagent**: `/home/drzbodun/fp/netagent/`

### Логи и данные

- **p0f log**: `/var/log/p0f.log`
- **p0f socket**: `/var/run/p0f.sock`
- **Upstream journal**: `journalctl -u fp-upstream`
- **TTL agent journal**: `journalctl -u fp-netagent`
- **H2 edge journal**: `journalctl -u fp-h2edge`

---

## Как управлять сервисами

Статусы:

```bash
systemctl status fp-h2edge
systemctl status fp-upstream
systemctl status p0f
systemctl status fp-netagent
```

Рестарт:

```bash
sudo systemctl restart fp-h2edge
sudo systemctl restart fp-upstream
sudo systemctl restart p0f
sudo systemctl restart fp-netagent
```

---

## Что является “Akamai-like” и какие ограничения

Сейчас реализовано:

- **TLS fingerprints**: JA3/JA4 (по ClientHello)
- **ClientHello tables**: cipher suites/extensions/curves/ALPN/etc (best-effort парсинг)
- **TCP/IP stack**: p0f (пассивная сигнатура/оценка distance/uptime и т.п.)
- **TTL**: eBPF (сырой TTL входящих IPv4 пакетов)
- **HTTP fingerprint (approx)**: хэш от набора HTTP заголовков + списка header names
- **HTTP/2 frame-level fingerprint (частично)**: preface/SETTINGS/WINDOW_UPDATE/PRIORITY (первичные сигналы)
- **TLS handshake dumps (best-effort)**: ClientHello record и первые server handshake records + парсинг ServerHello

Не реализовано “как в `tls.peet.ws` 1:1”:

- полный “Akamai HTTP fingerprint” и полноценная телеметрия **всех** фреймов (при необходимости расширяется в `fp-h2edge`)

---

## Быстрые проверки

Проверить, что сайт отвечает:

```bash
curl -skI https://kf58p1vqbctehrki.mooo.com/
```

Сводка fingerprints:

```bash
curl -sk https://kf58p1vqbctehrki.mooo.com/api/clean | head
```

TTL и TCP fingerprint:

```bash
curl -sk https://kf58p1vqbctehrki.mooo.com/api/ttl | head
curl -sk https://kf58p1vqbctehrki.mooo.com/api/tcp | head
```

H2 frame fingerprint (виден в `/api/all` как `h2_fp`, а также список настроек):

```bash
curl -sk https://kf58p1vqbctehrki.mooo.com/api/all | egrep 'h2_fp|h2_settings|h2_window_incr|h2_priority_frames' | head
```

TLS handshake dumps:

```bash
curl -sk https://kf58p1vqbctehrki.mooo.com/api/handshake | head
```

