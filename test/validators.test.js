const test = require('node:test');
const assert = require('node:assert/strict');
const { validateRegistration, validateName, cleanEmail, EMAIL_RE } = require('../lib/validators');

const ok = { fullName: 'Марія Пастух', email: 'Maria@Gmail.com', password: 'Qwerty123' };
const err = (patch) => validateRegistration({ ...ok, ...patch }).error;

test('коректна реєстрація: email у нижньому регістрі, ім’я без зайвих пробілів', () => {
  const r = validateRegistration({ ...ok, fullName: '  Марія   Пастух ', email: '  Maria@Gmail.com ' });
  assert.equal(r.error, undefined);
  assert.deepEqual(r.value, { fullName: 'Марія Пастух', email: 'maria@gmail.com', password: 'Qwerty123' });
});

test('порожнє тіло запиту та відсутні поля', () => {
  assert.equal(validateRegistration(undefined).error, 'Заповни всі поля');
  assert.equal(validateRegistration({}).error, 'Заповни всі поля');
  assert.equal(err({ fullName: '' }), 'Заповни всі поля');
  assert.equal(err({ email: '' }), 'Заповни всі поля');
  assert.equal(err({ password: '' }), 'Заповни всі поля');
});

test('поля не рядки (захист від підміни типів)', () => {
  assert.equal(err({ fullName: { $ne: 1 } }), 'Заповни всі поля');
  assert.equal(err({ email: ['a@b.cc'] }), 'Заповни всі поля');
  assert.equal(err({ password: 12345678 }), 'Заповни всі поля');
});

test('довжина імені', () => {
  assert.match(err({ fullName: 'А' }), /від 2 до 60/);
  assert.match(err({ fullName: 'а'.repeat(61) }), /від 2 до 60/);
  assert.equal(err({ fullName: 'а'.repeat(60) }), undefined);
});

for (const bad of ['abc', 'abc@', '@x.com', 'a@b', 'a b@x.com', 'a@@x.com', 'a@x.c']) {
  test(`некоректний email «${bad}»`, () => {
    assert.equal(err({ email: bad }), 'Вкажи коректну адресу email');
  });
}

test('занадто довгий email', () => {
  assert.equal(err({ email: 'a'.repeat(250) + '@x.com' }), 'Вкажи коректну адресу email');
});

test('вимоги до пароля', () => {
  assert.match(err({ password: 'abc123' }), /8 символів/);
  assert.match(err({ password: 'abcdefghij' }), /літери та цифри/);
  assert.match(err({ password: '1234567890' }), /літери та цифри/);
  assert.match(err({ password: 'a1'.repeat(40) }), /занадто довгий/);
});

test('межа bcrypt рахується в байтах, а не символах', () => {
  assert.match(err({ password: 'ж1'.repeat(30) }), /занадто довгий/);
  assert.equal(err({ password: 'ж1'.repeat(20) }), undefined);
});

test('cleanEmail', () => {
  assert.equal(cleanEmail('  A@B.CC '), 'a@b.cc');
  assert.equal(cleanEmail(null), '');
});

test('validateName', () => {
  assert.equal(validateName('  Анна  ').value, 'Анна');
  assert.ok(validateName('').error);
  assert.ok(validateName(' ').error);
  assert.ok(validateName('А').error);
  assert.ok(validateName('а'.repeat(61)).error);
  assert.ok(validateName(null).error);
});

test('EMAIL_RE', () => {
  assert.equal(EMAIL_RE.test('anna.k+tag@mail.example.com'), true);
  assert.equal(EMAIL_RE.test('anna@'), false);
});
