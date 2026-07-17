{
  "name": "nahadai-reminder-worker",
  "version": "2.0.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "wrangler dev",
    "deploy": "wrangler deploy",
    "check": "node --check src/index.js && node --check src/telegram.js"
  },
  "devDependencies": {
    "wrangler": "^4.0.0"
  }
}
