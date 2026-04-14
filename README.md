# panel-device-guard (API-only)

Отдельный сервис для временной блокировки пользователей (`disabled`) при превышении лимита устройств на основе **реальных подключений** из node logs WebSocket.

## Что делает

- Подключается к панели только по API (`/api/admin/token`, `/api/nodes`, `/api/users`, `/api/user/{username}`)
- Слушает логи нод через WebSocket `/api/node/{node_id}/logs`
- Парсит строки вида:
  - `from <ip>:... email: <user>`
  - Поддерживает IPv4 и IPv6 (включая формат `[ipv6]:port`)
- Считает уникальные source IP в скользящем окне `ACTIVE_WINDOW_SECONDS`
- Если `unique_ip > device_limit + EXTRA_DEVICES` в течение `VIOLATION_THRESHOLD` подряд проверок:
  - ставит `status=disabled`
  - добавляет метку в `note` с TTL (`[DGUARD] until=... prev=...`)
- По окончании TTL снимает блок обратно в `prev` (обычно `active`)
- Поддерживает whitelist по пользователям и IP
- Поддерживает `dry-run` режим (без реального изменения статуса)
- Поднимает встроенный web dashboard с авторизацией по логину/паролю из env
- В dashboard доступны ручные действия: `Ban` и `Unban`

## Структура проекта

- `src/config.py` — загрузка и валидация env-конфига
- `src/panel_api.py` — клиент API панели
- `src/log_parser.py` — разбор строк node logs
- `src/guard.py` — бизнес-логика блокировки/разблокировки
- `src/main.py` — точка входа и инициализация логгера
- `src/web.py` — HTTP frontend/API для просмотра состояния guard и ручных действий

## node-device-guard (агент на ноде)

Агент, устанавливаемый на каждую VPN-ноду. Получает список IP-адресов от panel-device-guard и мгновенно сбрасывает их активные соединения через `ss -K` (RST-пакет).

**Зачем:** когда panel-device-guard банит пользователя (ставит `status=disabled` в Marzban), уже установленные TCP-соединения продолжают работать. node-device-guard решает это: принудительно рвёт соединения через `ss -K dst <ip>` в момент бана. Работает с Xray/VLESS и любым другим TCP-прокси.

### Как работает

```
panel-device-guard (бан)
    └─ POST /kick {"ips": ["1.2.3.4", ...]}
           └─ node-device-guard
                  └─ ss -K dst 1.2.3.4   (RST → соединение немедленно рвётся)
```

### Переменные агента

| Переменная        | По умолчанию | Описание                                                                                 |
| ----------------- | ------------ | ---------------------------------------------------------------------------------------- |
| `NODE_KICK_PORT`  | `62010`      | Порт HTTP-сервера                                                                        |
| `NODE_KICK_TOKEN` | —            | Shared secret (Bearer token). Если не задан — эндпоинт `/kick` открыт без аутентификации |

### Переменные panel-device-guard для включения кика

| Переменная          | Описание                                                  |
| ------------------- | --------------------------------------------------------- |
| `NODE_KICK_ENABLED` | `true` / `false` — включить отправку kick-запросов        |
| `NODE_KICK_PORT`    | Порт агента (должен совпадать с `NODE_KICK_PORT` на ноде) |
| `NODE_KICK_TOKEN`   | Тот же токен, что задан на ноде                           |

### Деплой через Docker (рекомендуется)

```bash
cp .env.example .env
# Заполни NODE_KICK_TOKEN — тот же что в panel-device-guard .env
docker compose up -d
```

> `network_mode: host` и `cap_add: NET_ADMIN` обязательны — иначе `ss -K` не увидит соединения хоста.

### Деплой без Docker

```bash
apt install -y iproute2 python3 python3-pip
pip3 install aiohttp

NODE_KICK_PORT=62010 NODE_KICK_TOKEN=your-secret python3 agent.py
```

Для автозапуска через systemd:

```ini
# /etc/systemd/system/node-device-guard.service
[Unit]
Description=node-device-guard
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/node-device-guard/agent.py
Restart=always
Environment=NODE_KICK_PORT=62010
Environment=NODE_KICK_TOKEN=your-secret

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now node-device-guard
```

### Требования на ноде

- Linux с `iproute2` (`apt install iproute2`, обычно уже предустановлен)
- Python 3.10+ или Docker
- Порт `NODE_KICK_PORT` доступен только с сервера panel-device-guard (закрыть файрволом для остальных)

### Безопасность

- Всегда задавай `NODE_KICK_TOKEN` — случайную строку не менее 32 символов
- Закрой порт файрволом: разрешай только IP-адрес сервера с panel-device-guard
- IP валидируется через `ipaddress.ip_address()` перед передачей в `ss` — shell-инъекции невозможны

---

## Важно

- Сервис **не ходит в БД** напрямую.
- Работает только через HTTP/WS API панели.

## Запуск

1. Скопируйте `.env.example` в `.env` и задайте параметры.
2. Запустите:

- `docker compose up -d --build`

## Основные переменные

- `PANEL_BASE_URL` — URL панели (например `http://127.0.0.1:8000`)
- `PANEL_USERNAME`, `PANEL_PASSWORD` — API-учётка sudo-admin
- `EXTRA_DEVICES` — допуск `+N` к device_limit
- `ACTIVE_WINDOW_SECONDS` — окно активности для подсчёта IP
- `VIOLATION_THRESHOLD` — число подряд превышений до блока
- `BLOCK_TTL_SECONDS` — длительность временного блока
- `CHECK_INTERVAL_SECONDS` — интервал оценки состояния
- `NODE_LOGS_INTERVAL` — interval для node logs websocket
- `EMAIL_TO_USERNAME_REGEX` — преобразование `email` из логов в username
- `WHITELIST_USERNAMES` — CSV-список пользователей, которых guard не блокирует
- `WHITELIST_IPS` — CSV-список IP, которые игнорируются при подсчёте
  - Для IPv6 указывайте обычный адрес (без `[]`), например `2001:db8::1`
- `DRY_RUN` — если `true`, сервис только логирует действия, но не отправляет изменения пользователя
- `WEB_ENABLED` — `true` чтобы поднять встроенный web-дашборд (по умолчанию `false`)
- `WEB_PORT` — порт дашборда (по умолчанию `8080`)
- `WEB_USERNAME`, `WEB_PASSWORD` — логин/пароль для входа во frontend
- `WEB_SECRET_KEY` — ключ подписи сессий; если не задан — генерируется случайный (сессии сбрасываются при рестарте)
- `MANUAL_BLOCK_TTL_SECONDS` — TTL (сек) для ручного бана через UI по умолчанию
- `WEBHOOK_URL` — (опционально) URL для получения POST-уведомлений о бане и разбане
- `WEBHOOK_SECRET` — (опционально) секрет для подписи payload; если задан, каждый запрос содержит заголовок `X-Signature: sha256=<hmac>`

## Webhook-уведомления

Если задан `WEBHOOK_URL`, сервис отправляет `POST`-запрос с `Content-Type: application/json` при каждом бане или разбане.

Если задан `WEBHOOK_SECRET`, к запросу добавляется заголовок `X-Signature: sha256=<hmac-sha256>` — HMAC от тела запроса, ключ — значение `WEBHOOK_SECRET`. Алгоритм проверки совпадает с GitHub-вебхуками.

**Бан (auto и manual):**

```json
{
  "timestamp": 1744552800,
  "action": "ban",
  "trigger": "auto",
  "username": "john",
  "device_limit": 5,
  "active_ip_count": 12,
  "ips": ["1.2.3.4", "5.6.7.8"]
}
```

**Разбан:**

```json
{
  "timestamp": 1744552900,
  "action": "unban",
  "trigger": "manual",
  "username": "john"
}
```

- `timestamp` — Unix-время (UTC) в момент отправки запроса
- `trigger` — `"auto"` (сработала автоматика) или `"manual"` (через UI)
- Ошибка доставки логируется как warning, не влияет на работу guard

### Проверка подписи на принимающей стороне

Сравните заголовок `X-Signature` с HMAC-SHA256, вычисленным от **сырого тела** запроса и вашего секрета.

**Python:**

```python
import hashlib, hmac

def verify_signature(body: bytes, secret: str, header: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)

# во Flask/aiohttp:
body = await request.read()          # сырые байты, до парсинга JSON
sig  = request.headers.get("X-Signature", "")
if not verify_signature(body, "YOUR_SECRET", sig):
    return Response(status=403)
```

**Node.js:**

```js
const crypto = require("crypto");

function verifySignature(body, secret, header) {
  const expected =
    "sha256=" + crypto.createHmac("sha256", secret).update(body).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(header));
}

// во Express:
app.post("/hook", express.raw({ type: "*/*" }), (req, res) => {
  if (
    !verifySignature(req.body, "YOUR_SECRET", req.headers["x-signature"] ?? "")
  )
    return res.sendStatus(403);
  const payload = JSON.parse(req.body);
  // ...
});
```

> **Важно:** всегда читайте тело запроса **до** `JSON.parse` / `.json()`, иначе байты могут не совпасть. Используйте `hmac.compare_digest` / `timingSafeEqual` для защиты от timing-атак.

## Что показывает frontend

- Пользователей, которых guard сейчас учитывает (активные IP и/или активная guard-метка)
- Текущее число активных IP
- Список IP и время последней активности
- Список конфигов (`email` из логов Xray), с которых шли подключения
- Кнопки `Ban` и `Unban`

## Примечания по точности

Подсчёт по IP — практичный, но не идеальный способ (NAT/мобильные сети). Для снижения false positive используйте:

- `VIOLATION_THRESHOLD >= 2`
- умеренный `BLOCK_TTL_SECONDS`
- аккуратный `ACTIVE_WINDOW_SECONDS` (обычно 300–900)

## Рекомендации по настройке ключевых параметров

### `ACTIVE_WINDOW_SECONDS`

Сколько секунд назад засчитывается IP как «активный». Guard считает уникальные IP за этот период.

- **Слишком мало (< 120 с):** частые ротации IP (особенно мобильный интернет) не успевают «исчезнуть» — пики будут ложными.
- **Слишком много (> 1200 с):** старые IP остаются в счётчике слишком долго, повышая false positive.
- **Рекомендуется:** `300` – `600` с (5–10 минут). При нестабильных сетях у пользователей — ближе к 600.

### `CHECK_INTERVAL_SECONDS`

Как часто guard проверяет каждого пользователя и сравнивает число активных IP с лимитом.

- **Слишком мало (< 5 с):** избыточная нагрузка на API панели, нет реальной пользы.
- **Слишком много (> 60 с):** нарушения обнаруживаются поздно, `VIOLATION_THRESHOLD` накапливается медленно.
- **Рекомендуется:** `10` – `30` с. При `VIOLATION_THRESHOLD=3` и `CHECK_INTERVAL=10` блок ставится ~через 30 с после первого превышения.

### `VIOLATION_THRESHOLD`

Сколько раз подряд должно быть зафиксировано превышение, прежде чем пользователь будет заблокирован. Счётчик сбрасывается при каждой нормальной проверке.

- **`1`:** блокирует при первом же превышении — максимальная жёсткость, высокий риск false positive (один лишний IP из-за NAT = бан).
- **`2`:** хороший баланс для большинства случаев.
- **`3` и выше:** защита от кратковременных пиков, но нарушитель работает дольше до блока.
- **Рекомендуется:** `2` – `3`. При параноидальном режиме — `2` + строгий `ACTIVE_WINDOW_SECONDS`.

### Примеры конфигураций

| Сценарий                         | `ACTIVE_WINDOW_SECONDS` | `CHECK_INTERVAL_SECONDS` | `VIOLATION_THRESHOLD` |
| -------------------------------- | ----------------------- | ------------------------ | --------------------- |
| Жёсткий (корпоративный)          | 300                     | 10                       | 2                     |
| Сбалансированный (рекомендуется) | 600                     | 15                       | 3                     |
| Мягкий (мобильные пользователи)  | 900                     | 30                       | 4                     |

### Пример: лимит 5 устройств + запас +5

Если в панели у пользователей стоит `device_limit=5`, но вы хотите дать реальный запас ещё на 5 устройств (например, на случай переподключений или мобильного интернета), используйте:

```env
EXTRA_DEVICES=5
ACTIVE_WINDOW_SECONDS=600
CHECK_INTERVAL_SECONDS=15
VIOLATION_THRESHOLD=3
BLOCK_TTL_SECONDS=1800
```

**Как это работает на практике:**

- Guard разрешает до `5 + 5 = 10` уникальных IP в течение последних 10 минут.
- Если превышение зафиксировано 3 раза подряд (т.е. ~45 секунд устойчивого нарушения), пользователь блокируется на 30 минут.
- Краткосрочные всплески (смена IP, переподключения) не вызывают бан.

**Что означает каждый параметр в этом сценарии:**

| Параметр                 | Значение | Смысл                                                       |
| ------------------------ | -------- | ----------------------------------------------------------- |
| `EXTRA_DEVICES`          | `5`      | Разрешает до 10 одновременных IP вместо 5                   |
| `ACTIVE_WINDOW_SECONDS`  | `600`    | IP считается активным 10 минут после последнего подключения |
| `CHECK_INTERVAL_SECONDS` | `15`     | Проверка каждые 15 секунд                                   |
| `VIOLATION_THRESHOLD`    | `3`      | Бан после 3 проверок подряд с превышением (~45 с)           |
| `BLOCK_TTL_SECONDS`      | `1800`   | Бан на 30 минут, затем автоматическое снятие                |
