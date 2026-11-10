// Перевірка даних реєстрації та профілю. Окремий файл, щоб його можна було тестувати без сервера й бази.

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function cleanName(value) {
  return typeof value === 'string' ? value.trim().replace(/\s+/g, ' ') : '';
}

function cleanEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

/** Повертає { error } або { value: { fullName, email, password } } */
function validateRegistration(body) {
  const b = body || {};
  const fullName = cleanName(b.fullName);
  const email = cleanEmail(b.email);
  const password = typeof b.password === 'string' ? b.password : '';

  if (!fullName || !email || !password) return { error: 'Заповни всі поля' };
  if (fullName.length < 2 || fullName.length > 60) return { error: 'Ім’я має містити від 2 до 60 символів' };
  if (email.length > 254 || !EMAIL_RE.test(email)) return { error: 'Вкажи коректну адресу email' };
  if (password.length < 8) return { error: 'Пароль має містити щонайменше 8 символів' };
  if (Buffer.byteLength(password, 'utf8') > 72) return { error: 'Пароль занадто довгий (до 72 байтів)' };
  if (!/\p{L}/u.test(password) || !/\d/.test(password)) return { error: 'Пароль має містити літери та цифри' };
  return { value: { fullName, email, password } };
}

/** Повертає { error } або { value: ім'я } */
function validateName(value) {
  const fullName = cleanName(value);
  if (!fullName) return { error: 'Вкажи ім\'я' };
  if (fullName.length < 2 || fullName.length > 60) return { error: 'Ім’я має містити від 2 до 60 символів' };
  return { value: fullName };
}

module.exports = { EMAIL_RE, validateRegistration, validateName, cleanEmail };
