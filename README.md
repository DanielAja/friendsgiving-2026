# Friendsgiving 2026 potluck

A tiny, throwaway sign-up page: everyone says what they're bringing, with no accounts.

- **Add a dish:** your name, the dish, a category, how many, and an optional note.
- **Edit or remove it:** the device that added a dish can change it. To change it from another device, set an optional password when you add it (or later, from the device that added it).
- **Open:** anyone with the link can see the list and add to it.
- **Disposable:** everything is deleted automatically on 1 January 2027.

## How it works
- `docs/` is a static page served by GitHub Pages.
- `worker/` is a Cloudflare Worker with a D1 database (both free tier). It stores the list and enforces who can edit what.

## Abuse checks (done on the server, not in the browser)
- Edits need proof: the random edit token kept by the device that added the dish (only its SHA-256 is stored), or the dish's password (stored as salted PBKDF2, never in plain text).
- Rate limits per connection: 8 new dishes an hour and 20 a day, 60 edits an hour, 5 wrong passwords per dish per 15 minutes, and 20 wrong passwords an hour.
- At most 400 dishes, length limits on every field, and the API only accepts calls from this page.
- IP addresses are never stored, only a salted hash used as a rate-limit key.

## Run your own
1. `cd worker`, then `npx wrangler d1 create friendsgiving-2026` and put the id in `wrangler.jsonc`.
2. Run `npx wrangler d1 migrations apply friendsgiving-2026 --remote`, then `openssl rand -base64 32 | npx wrangler secret put IP_SALT`, then `npx wrangler deploy`.
3. Put your Worker URL in `docs/config.js` and your Pages URL in `ALLOWED_ORIGINS`, then turn on GitHub Pages for `/docs`.

MIT licensed.
