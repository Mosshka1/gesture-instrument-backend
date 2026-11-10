const test = require('node:test');
const assert = require('node:assert/strict');
const { rateLimit } = require('../lib/rateLimit');

function fakeRes() {
  return {
    code: 200,
    headers: {},
    body: null,
    set(k, v) { this.headers[k] = v; return this; },
    status(c) { this.code = c; return this; },
    json(b) { this.body = b; return this; },
  };
}

test('пропускає запити в межах ліміту', () => {
  const mw = rateLimit(3, 1000);
  let passed = 0;
  for (let i = 0; i < 3; i++) mw({ ip: '1.1.1.1' }, fakeRes(), () => passed++);
  assert.equal(passed, 3);
});

test('після перевищення повертає 429 із Retry-After', () => {
  const mw = rateLimit(2, 60_000);
  const res = fakeRes();
  let passed = 0;
  for (let i = 0; i < 3; i++) mw({ ip: '2.2.2.2' }, i === 2 ? res : fakeRes(), () => passed++);
  assert.equal(passed, 2);
  assert.equal(res.code, 429);
  assert.ok(Number(res.headers['Retry-After']) > 0);
  assert.match(res.body.error, /Забагато/);
});

test('різні IP-адреси рахуються окремо', () => {
  const mw = rateLimit(1, 1000);
  let passed = 0;
  mw({ ip: 'a' }, fakeRes(), () => passed++);
  mw({ ip: 'b' }, fakeRes(), () => passed++);
  assert.equal(passed, 2);
});

test('після закінчення вікна лічильник скидається', () => {
  let t = 1000;
  const mw = rateLimit(1, 500, () => t);
  let passed = 0;
  mw({ ip: 'x' }, fakeRes(), () => passed++);
  const blocked = fakeRes();
  mw({ ip: 'x' }, blocked, () => passed++);
  assert.equal(blocked.code, 429);
  t += 600;
  mw({ ip: 'x' }, fakeRes(), () => passed++);
  assert.equal(passed, 2);
});
