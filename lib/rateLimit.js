// Проста «лінійка» запитів: не більше max запитів за вікно часу з однієї IP-адреси.
// now — функція часу (можна підміняти в тестах).
function rateLimit(max, windowMs, now = Date.now) {
  const hits = new Map();
  const timer = setInterval(() => {
    const t = now();
    for (const [k, v] of hits) if (v.reset < t) hits.delete(k);
  }, windowMs);
  if (timer.unref) timer.unref();

  return (req, res, next) => {
    const t = now();
    let h = hits.get(req.ip);
    if (!h || h.reset < t) h = { count: 0, reset: t + windowMs };
    h.count++;
    hits.set(req.ip, h);
    if (h.count > max) {
      res.set('Retry-After', String(Math.ceil((h.reset - t) / 1000)));
      return res.status(429).json({ error: 'Забагато спроб. Зачекай кілька хвилин і спробуй ще раз' });
    }
    next();
  };
}

module.exports = { rateLimit };
