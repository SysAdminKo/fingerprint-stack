# Fingerprint stack (H2 Edge + upstream + net agents)

Этот репозиторий/рабочая директория описывает стенд, который собирает и отображает максимум информации о fingerprint клиента при заходе на:

- `https://<your-domain>`

Цель: приблизиться по набору данных/выводу к `tls.peet.ws`, но на своей машине.

---

## Что сделано

### 1) Публичный HTTPS сайт

- **Домен**: `<your-domain>`
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
- `X-TLS-Remote-Addr` (client `ip:port` внешней TLS-сессии — для привязки к `tcp.stream` в `.pcap`)
- `X-TLS-ClientHello-Record-B64`, `X-TLS-ClientHello-Record-Len`, `X-TLS-ClientHello-Record-Hex`
- `X-TLS-ServerHandshake-Records-B64`, `X-TLS-ServerHello-JSON`

### Edge timing (тайминги)

Состояние считается **отдельно на каждое TCP-соединение** (один `handleConn` в `fp-h2edge`), без глобальной карты по адресу клиента.

**Ответ клиенту (edge → браузер):**

- `X-Edge-TTFB-MS` — время от начала обработки запроса до **первого** `WriteHeader`/`Write` в сторону клиента (TTFB с точки зрения edge).

**Запрос к upstream (только проксируемый путь; edge → `fp-upstream`):**

- `X-Edge-Request-Start-Unix` — `UnixNano` момента начала хендлера (целое число в строке).
- `X-Edge-Request-Interval-MS` — миллисекунды с момента **завершения предыдущего** запроса на **этом же** HTTP/2 соединении до начала текущего; не передаётся (или 0 не выставляется), если это первый запрос на соединении.
- `X-Edge-Prev-TTFB-MS` — TTFB **предыдущего** ответа на этом соединении (мс); не передаётся, если нечего с чем сравнить.

Upstream принимает эти поля только с **доверенного** адреса (`FP_TRUSTED_PROXY_CIDRS`) и кладёт их в JSON как `extra.edge_timing`:

- `request_start_unix_ns`
- `request_interval_ms`
- `prev_ttfb_ms`

**HTTP/2 `frame_log` (начало соединения):** в каждом элементе есть `delta_ms` — миллисекунды от **предыдущего** входящего кадра; для первого кадра после client preface — от момента окончания чтения preface. Окно чтения задаётся `H2EDGE_H2_CAPTURE_MS` / `H2EDGE_H2_MAX_FRAMES`.

**Ограничение:** при **нескольких параллельных потоках** HTTP/2 на одном соединении интервалы и «предыдущий TTFB» могут **пересекаться** по времени; метрики в таком случае условные (best-effort).

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
  - `/api/pcap/result` — получение результата capture (ZIP: `.pcap`, снапшот `/api/all`, фрагмент **journal** `fp-h2edge` с `pcap_token`)
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
2) навигация на `GET /__close?next=/?pcap_token=<token>&pcap_step=1` на edge:
   - edge отдаёт небольшой HTML с client-side redirect на `next`
   - затем edge закрывает текущий HTTP/2 коннект (чтобы следующий запрос открыл новый TCP/TLS session)
3) загрузка страницы `/?pcap_token=<token>&pcap_step=1`
   - страница делает второй `__close` (best-effort) и переходит на `/?pcap_token=<token>&pcap_step=2`
   - затем удаляет `pcap_step` из URL (оставляя токен) и продолжает polling результата
4) загрузка/обновления страницы с `?pcap_token=` открывают новый TCP/TLS коннект, который должен попасть в окно capture
5) во время capture UI дополнительно дёргает `/ws` (best-effort), чтобы WebSocket-handshake трафик попал в `.pcap`
6) polling `GET /api/pcap/result?probe=1&token=<token>` (пока capture идёт — `202`)
7) скачивание **ZIP** через iframe: `GET /api/pcap/result?token=<token>` (attachment download), затем auto-reload

Как сопоставлять JSON и `.pcap`:

- В JSON смотри `tls.remote_addr` (например `95.31.2.36:53964`) — это внешний client `ip:port` на edge.
- В JSON смотри `extra.handshake_dump.client_hello_record_len` и `extra.handshake_dump.client_hello_record_hex_prefix` — это “подпись” захваченного edge TLS record.
- В Wireshark фильтруй по порту: `ip.addr == <client_ip> && tcp.port == <port>` и ищи `tls.handshake.type == 1` (ClientHello). Сверяй длину record и hex-префикс с JSON.

Переменные окружения upstream:

- `FP_PUBLIC_HOST` — домен/хост, который отображается в UI (например, в `<title>` страницы). Если не задано, берётся `Host` из запроса.
- `FP_ACCESS_LOG` — если `1`, логирует каждый HTTP запрос в journal (`method`, `path`, `status`, `bytes`, `dur`).
- `FP_README_PATH` — путь к `README.md`, который отображается в `/readme` и `/api/readme`. Если не задан, `/readme` может вернуть `500` (зависит от того, где запущен сервис).
- `FP_WS_PUBLIC_URL` — полный URL WebSocket для UI (переопределяет поведение по умолчанию). Если пусто, страница сама подключается к **`wss://<hostname>:8443/ws`** (и `ws://<hostname>:8443/ws` по HTTP).
- `FP_WS_FANOUT` — сколько параллельных WebSocket соединений открывать во время capture (по умолчанию `2`).
- `FP_WS_PAYLOAD_BYTES` — размер payload (в байтах), который браузер отправляет в WS во время capture (по умолчанию `4096`).
- `FP_WS_INTERVAL_MS` — интервал отправки WS сообщений в миллисекундах (по умолчанию `80`).
- `FP_WS_MAX_MS` — сколько миллисекунд держать WS “blast” (по умолчанию `13000`).
- `FP_PCAP_EXTRA_PORTS` — **дополнительные** TCP-порты для `tcpdump` (через запятую), **в дополнение** к обязательным **`443` и `8443`** (они всегда включаются в фильтр, чтобы в `.pcap` попадали и HTTPS, и `wss` на отдельном listener).
- `FP_PCAP_IFACE` — интерфейс для `tcpdump` (по умолчанию `any`)
- `FP_PCAP_TCPDUMP` — путь до `tcpdump` (по умолчанию `/usr/sbin/tcpdump`)
- `FP_PCAP_SAVE_DIR` — директория, куда **сохраняются** все `.pcap`, рядом снапшот `/api/all` и файл **`-h2edge.log`** (по умолчанию `/var/lib/fp/pcap`)
- `FP_H2EDGE_JOURNAL_UNIT` — имя systemd-юнита для `journalctl` при сборе строк лога edge в `-h2edge.log` (по умолчанию `fp-h2edge`). Нужны права на чтение journal (обычно root как у `fp-upstream`).
- `FP_PCAP_DIR` — директория для временных `.pcap` (legacy `/api/pcap`, по умолчанию `/tmp/fp-pcaps`)
- `FP_TRUSTED_PROXY_CIDRS` — список CIDR (через запятую), откуда upstream **доверяет** proxy-заголовкам от edge (`X-*`, `JA3`, `X-Forwarded-For`). По умолчанию: `127.0.0.1/8,::1/128`

**`fp-h2edge` (edge, дополнительно):**

- `H2EDGE_WS_LISTEN` — отдельный TLS listener **только HTTP/1.1** для полноценного WebSocket (например `0.0.0.0:8443`). Тот же сертификат, что и у основного listener. Если пусто — второй порт не поднимается.
- `H2EDGE_WS_RELAY_SECONDS` — сколько секунд после `101 Switching Protocols` держать соединение и обмениваться WS-кадрами (по умолчанию `12`).
- `H2EDGE_WS_SERVER_INTERVAL_MS` — как часто edge отправляет server→client WS сообщение во время relay (по умолчанию `800`).
- `H2EDGE_WS_SERVER_MSG_BYTES` — размер server→client WS сообщения (байт) во время relay (по умолчанию `80`).
- `H2EDGE_H2_CAPTURE_MS` — сколько миллисекунд читать входящие HTTP/2 кадры после preface (по умолчанию `800`, макс. `5000`).
- `H2EDGE_H2_MAX_FRAMES` — максимум кадров в `frame_log` / в расчёте хэша (по умолчанию `256`, макс. `2048`).
- `H2EDGE_H2_STOP_AFTER_HEADERS` — если `1`, остановка захвата после первого `SETTINGS`+`HEADERS` (старое поведение; по умолчанию выкл.).
- `H2EDGE_CLOSE_DELAY_MS` — задержка перед принудительным закрытием HTTP/2 соединения в `GET /__close` (мс; по умолчанию `250`). Меньшее значение увеличивает шанс, что следующий запрос откроет новый TCP/TLS коннект во время capture.
- `H2EDGE_ACCESS_LOG` — если `1`, логирует каждый HTTP/2 запрос (включая проксирование) в journal. Поля: `method`, `path`, `ip`, `status`, `bytes`, `dur_ms`, **`interval_ms`** (мс с конца предыдущего запроса на этом соединении), **`prev_ttfb_ms`** (TTFB предыдущего ответа), **`ttfb_ms`** (TTFB текущего ответа клиенту), **`pcap_token`** (токен из `?pcap_token=` на первом запросе с ним; дальше на том же TCP закрепляется для всех запросов; `-` если не привязан), `ua`. Нужен для выгрузки `-h2edge.log` рядом с pcap.
- `H2EDGE_WS_ACCESS_LOG` — если `1`, логирует каждый WS upgrade/relay на `:8443` (статистика кадров/байт/длительность, поле **`pcap_token`** если передан в query WebSocket URL — UI добавляет его при `?pcap_token=` на странице).

Для захвата трафика на `8443` в `.pcap` достаточно открыть порт в firewall: `443` и `8443` всегда включены в BPF-фильтр в коде (а `FP_PCAP_EXTRA_PORTS` — только “дополнения”).

Формат сохранения:

- `.pcap`: `handshake-<UTC>-<ip>-<token>.pcap`
- рядом снапшот `/api/all`: `handshake-<UTC>-<ip>-<token>-api-all.json`
- фрагмент journal edge: `handshake-<UTC>-<ip>-<token>-h2edge.log` (пишется по окончании `tcpdump`; при скачивании ZIP делается повторная попытка, если файла не было). В файл попадают строки с `pcap_token=<token>` **и** access-строки `h2` / `ws` с `ip=<тот же client ip, что и в capture>`, в расширенном временном окне вокруг capture.
- при скачивании через `/api/pcap/result` отдаётся ZIP: `handshake-<UTC>-<ip>-<token>.zip` с тремя файлами выше (`.pcap`, JSON, `-h2edge.log`)

### 5) TCP/IP stack fingerprint (p0f)

Поднят `p0f` как системный сервис и слушает unix socket:

- `/var/run/p0f.sock`

Upstream по `client_ip` делает запрос в `p0f-client` и отображает/возвращает результат.
`client_ip` берётся из `X-Forwarded-For` **только если** запрос пришёл от доверенного proxy (см. `FP_TRUSTED_PROXY_CIDRS`), иначе используется `RemoteAddr`.

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

1) Клиент приходит на `<your-domain>:443`
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
   - `X-TLS-Remote-Addr`
   - `X-TLS-ClientHello-Record-B64`, `X-TLS-ClientHello-Record-Len`, `X-TLS-ClientHello-Record-Hex`
   - `X-TLS-ServerHandshake-Records-B64`, `X-TLS-ServerHello-JSON`
   - при необходимости: `X-Edge-Request-Start-Unix`, `X-Edge-Request-Interval-MS`, `X-Edge-Prev-TTFB-MS` (см. раздел **Edge timing**)
5) Upstream агрегирует:
   - из заголовков выше
   - из `p0f` (TCP/IP stack)
   - из `fp-netagent` (TTL)
6) Upstream отдаёт HTML + JSON API

---

## Где что находится (пути на этой машине)

### Конфиги

- **Let's Encrypt (certbot)**:
  - `/etc/letsencrypt/live/<your-domain>/fullchain.pem`
  - `/etc/letsencrypt/live/<your-domain>/privkey.pem`
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

- **H2 edge (frame-level)**: `/home/drzbodun/fingerprint-stack/fp/h2edge/`
- **Upstream сервис**: `/home/drzbodun/fingerprint-stack/fp/upstream/`
- **TTL netagent**: `/home/drzbodun/fingerprint-stack/fp/netagent/`

### Автотесты (Go)

Юнит-тесты покрывают изолированную логику (без полного e2e TLS+H2+реального tcpdump/eBPF):

```bash
(cd fp/h2edge && go test ./...)
(cd fp/upstream && go test -short ./...)   # без сетевого smoke
(cd fp/upstream && go test ./...)          # + TestBuildPayload_smoke (p0f-client + TTL API)
(cd tools/wsprobe && go test ./...)
```

`fp/netagent` (Python + BPF) автотестами здесь не покрывается.

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

## Быстрая замена домена целиком (автоматизация)

Скрипт `deploy/set-domain.sh` автоматизирует “переезд” на новый домен:

- выпускает/обновляет сертификат Let’s Encrypt для нового домена через `certbot --standalone` (HTTP-01)
- временно останавливает `fp-h2edge`, чтобы освободить `:80` для ACME challenge
- обновляет пути `H2EDGE_CERT/H2EDGE_KEY` на `/etc/letsencrypt/live/<domain>/{fullchain.pem,privkey.pem}`
- выставляет `FP_PUBLIC_HOST=<domain>` (чтобы UI отображал правильный домен)
- пишет env-файлы в `/etc/fp/` и ставит systemd drop-in’ы, затем перезапускает `fp-upstream` и `fp-h2edge`

Запуск:

```bash
cd /home/drzbodun/fingerprint-stack
sudo ./deploy/set-domain.sh new.example.com --email you@example.com
```

Требования:

- DNS `A/AAAA` для нового домена указывает на этот сервер
- входящий `:80` доступен из интернета (для HTTP-01)
- `certbot` установлен и работает

Примечание: скрипт меняет **UI-домен** (`FP_PUBLIC_HOST`) и **TLS сертификат** (`H2EDGE_CERT/H2EDGE_KEY`). Сам по себе `FP_PUBLIC_HOST` сертификаты не перевыпускает.

---

## Полная установка на новый сервер (автоматически)

Скрипт `deploy/install.sh` разворачивает проект на новом сервере “под ключ”:

- ставит необходимые пакеты и зависимости (certbot, tcpdump, p0f, BCC/eBPF для TTL-агента, toolchain)
- ставит Go (если нужно) и собирает `fp-h2edge` / `fp-upstream`
- устанавливает бинарники в `/usr/local/bin`
- создаёт и включает systemd-сервисы: `fp-h2edge`, `fp-upstream`, `fp-netagent`, `p0f`
- может выпустить сертификат Let’s Encrypt для домена (certbot standalone) и сразу стартовать edge на `:80/:443`

### Non-interactive (через CLI параметры)

```bash
cd /home/drzbodun/fingerprint-stack
sudo ./deploy/install.sh --domain new.example.com --email you@example.com
```

### Установка одной командой (на новом сервере)

Полный деплой (клонирование + зависимости + systemd + Let’s Encrypt):

```bash
curl -fsSL https://raw.githubusercontent.com/SysAdminKo/fingerprint-stack/master/deploy/install.sh | sudo bash -s -- --domain YOUR.DOMAIN --email YOU@EXAMPLE.COM
```

Без выпуска сертификата (поставить сервисы и поднять локально/за прокси):

```bash
curl -fsSL https://raw.githubusercontent.com/SysAdminKo/fingerprint-stack/master/deploy/install.sh | sudo bash -s -- --issue-cert no
```

Только план (без изменений на сервере):

```bash
curl -fsSL https://raw.githubusercontent.com/SysAdminKo/fingerprint-stack/master/deploy/install.sh | bash -s -- --dry-run --issue-cert no
```

### Установка на “чистый” сервер (скрипт сам клонирует репозиторий)

```bash
sudo ./deploy/install.sh \
  --repo-url https://github.com/SysAdminKo/fingerprint-stack.git \
  --install-dir /opt/fingerprint-stack \
  --ref v1.2.3 \
  --domain new.example.com \
  --email you@example.com
```

Примечание: если запустить повторно с `--update yes` и без `--ref`, будет выбрана **дефолтная ветка `origin/HEAD`** (обычно `main`) и выполнен `git pull --ff-only`.

### Interactive (задаёт вопросы, если не передано флагами)

```bash
cd /home/drzbodun/fingerprint-stack
sudo ./deploy/install.sh
```

Поддерживаемые параметры см. в `./deploy/install.sh --help`.

---

## Что является “Akamai-like” и какие ограничения

Сейчас реализовано:

- **TLS fingerprints**: JA3/JA4 (по ClientHello)
- **ClientHello tables**: cipher suites/extensions/curves/ALPN/etc (best-effort парсинг)
- **TCP/IP stack**: p0f (пассивная сигнатура/оценка distance/uptime и т.п.)
- **TTL**: eBPF (сырой TTL входящих IPv4 пакетов)
- **HTTP fingerprint (улучшенный)**: хэш от `Method` + `Host` + `path` + длины query + расширенного набора заголовков + **отфильтрованных** имён заголовков (без hop-by-hop / `X-Forwarded-*`). Считается **до** инъекции edge-заголовков (`X-H2-*`, `JA3`, …), чтобы не смешивать клиент и прокси.
- **HTTP/2 frame-level fingerprint**: preface + **последовательность входящих кадров** (тип, stream id, длина, flags) в пределах окна захвата; агрегаты SETTINGS / WINDOW_UPDATE / PRIORITY; `X-H2-FP` включает компактную `frame_seq`. Параметры: `H2EDGE_H2_CAPTURE_MS`, `H2EDGE_H2_MAX_FRAMES`, опционально ранний стоп `H2EDGE_H2_STOP_AFTER_HEADERS=1` (как раньше).
- **TLS handshake dumps (best-effort)**: ClientHello record и первые server handshake records + парсинг ServerHello

Ограничения (не “как коммерческий WAF 1:1”):

- Телеметрия H2 идёт **только в начале соединения** (до `http2.Server.ServeConn`): дальнейшие кадры того же HTTP/2 connection после отдачи запроса edge **не** логируются отдельным тапом (это потребовало бы полного tee всего TLS потока).
- **Порядок HTTP/2 псевдо-заголовков** в HPACK в этот хэш не попадает (в `net/http` порядок заголовков как map недоступен).
- **Полный “Akamai HTTP fingerprint”** как закрытая эвристика внешних сервисов не воспроизводится дословно; набор сигналов расширяемый через `computeHTTPFP` в `fp-h2edge`.

---

## Безопасность / доверительная граница (важно)

`fp-upstream` отображает fingerprints, которые приходят от edge в виде заголовков (`X-H2-*`, `X-TLS-*`, `X-CH-*`, `X-JA4`, `JA3`, `X-HTTP-FP`, `X-WS-*`).

Чтобы клиент не мог подделать эти значения, upstream **доверяет** `X-*` / `JA3` / `X-Forwarded-For` **только если запрос пришёл от доверенного proxy** (по `RemoteAddr`).

- по умолчанию доверены только локальные адреса: `127.0.0.1/8,::1/128`
- настраивается через `FP_TRUSTED_PROXY_CIDRS`

Если `RemoteAddr` **не** входит в `FP_TRUSTED_PROXY_CIDRS`, upstream игнорирует `X-Forwarded-For` и все edge-заголовки (они будут пустыми в UI/API).
В `/api/all` дополнительно добавлен блок `extra.trusted_proxy` с флагом `ok` и текущим списком `cidrs`.

## Быстрые проверки

Проверить, что сайт отвечает:

```bash
curl -skI https://<your-domain>/
```

Сводка fingerprints:

```bash
curl -sk https://<your-domain>/api/clean | head
```

TTL и TCP fingerprint:

```bash
curl -sk https://<your-domain>/api/ttl | head
curl -sk https://<your-domain>/api/tcp | head
```

H2 frame fingerprint (виден в `/api/all` как `h2_fp`, а также список настроек):

```bash
curl -sk https://<your-domain>/api/all | egrep 'h2_fp|h2_settings|h2_window_incr|h2_priority_frames' | head
```

TLS handshake dumps:

```bash
curl -sk https://<your-domain>/api/handshake | head
```

