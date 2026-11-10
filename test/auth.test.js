const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');

process.env.JWT_SECRET = 'test-secret';
const authMiddleware = require('../middleware/auth');

function run(headers) {
  const res = { code: null, body: null, status(c) { this.code = c; return this; }, json(b) { this.body = b; return this; } };
  const req = { headers };
  let nextCalled = false;
  authMiddleware(req, res, () => { nextCalled = true; });
  return { req, res, nextCalled };
}

test('без заголовка — 401', () => {
  const r = run({});
  assert.equal(r.res.code, 401);
  assert.equal(r.nextCalled, false);
});

test('не Bearer — 401', () => {
  assert.equal(run({ authorization: 'Basic abc' }).res.code, 401);
});

test('довільний токен — 401', () => {
  assert.equal(run({ authorization: 'Bearer не.токен' }).res.code, 401);
});

test('токен, підписаний чужим ключем — 401', () => {
  const t = jwt.sign({ userId: 1 }, 'інший-ключ');
  assert.equal(run({ authorization: `Bearer ${t}` }).res.code, 401);
});

test('прострочений токен — 401', () => {
  const t = jwt.sign({ userId: 1 }, 'test-secret', { expiresIn: -10 });
  assert.equal(run({ authorization: `Bearer ${t}` }).res.code, 401);
});

test('чинний токен пропускає й записує userId', () => {
  const t = jwt.sign({ userId: 42 }, 'test-secret', { expiresIn: '1h' });
  const r = run({ authorization: `Bearer ${t}` });
  assert.equal(r.nextCalled, true);
  assert.equal(r.req.userId, 42);
});
