// Where the shared list lives. Fork it? Deploy worker/ and put your Worker URL here.
window.FG_CONFIG = {
  apiBase: /^(localhost|127\.0\.0\.1)$/.test(location.hostname)
    ? 'http://127.0.0.1:8787'
    : 'https://friendsgiving-2026.ajadigital.workers.dev',
};
