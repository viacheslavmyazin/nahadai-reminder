# Нагадай — Telegram V2

Модульна версія Cloudflare Worker:

- `src/index.js` — чинний Worker, API, авторизація, Cron і D1;
- `src/telegram.js` — окремий Telegram-модуль;
- webhook: `/api/telegram/webhook`.

## Що вже працює

- `/start` і `/menu`;
- кнопки `Сьогодні`, `Прострочені`, `Активні`, `Виконані`;
- список задач із D1;
- `Виконано` і `На завтра`;
- кнопка переходу в Mini App;
- докладні логи Telegram у Cloudflare Observability.

## Встановлення через Cloudflare Dashboard

Cloudflare Dashboard у звичайному редакторі часто показує один файл. Найнадійніше розгорнути цей проєкт через Wrangler або підключити GitHub-репозиторій.

### Wrangler

1. Встановити Node.js.
2. У папці проєкту виконати:

```bash
npm install
npx wrangler login
npx wrangler deploy
```

3. Переконатися, що в Worker збережені bindings/secrets:

- `DB` — D1 binding;
- `TELEGRAM_BOT_TOKEN`;
- `TELEGRAM_WEBHOOK_SECRET`;
- `APP_URL`;
- інші наявні змінні авторизації.

## Перевірка

Після deploy надіслати боту `/start`.

У логах повинно бути:

```text
POST /api/telegram/webhook
Telegram update { hasMessage: true }
```
