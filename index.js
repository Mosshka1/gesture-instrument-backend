const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const { PrismaClient } = require('@prisma/client');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();
const authMiddleware = require('./middleware/auth');

const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const upload = multer({ dest: 'uploads/' });

// Окремий завантажувач для власних звуків: зберігає розширення файлу,
// обмежує розмір (10 МБ) і пропускає лише аудіофайли
const soundUpload = multer({
  storage: multer.diskStorage({
    destination: 'uploads/',
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase().slice(0, 8);
      const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
      cb(null, unique + ext);
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('audio/')) cb(null, true);
    else cb(new Error('NOT_AUDIO'));
  },
});

function handleSoundUpload(req, res, next) {
  soundUpload.single('audio')(req, res, (err) => {
    if (!err) return next();
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'Файл завеликий (максимум 10 МБ)' });
    }
    if (err.message === 'NOT_AUDIO') {
      return res.status(400).json({ error: 'Можна завантажувати лише аудіофайли' });
    }
    console.error(err);
    return res.status(500).json({ error: 'Щось пішло не так' });
  });
}

function sendServerError(res, error) {
  console.error(error);
  res.status(500).json({ error: 'Щось пішло не так' });
}

function makeToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/auth/register', async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
      return res.status(400).json({ error: 'Заповни всі поля' });
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'Користувач з таким email вже існує' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { fullName, email, password: hashedPassword },
    });

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: { id: user.id, fullName: user.fullName, email: user.email },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Щось пішло не так' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Заповни всі поля' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'Невірний email або пароль' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Невірний email або пароль' });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: { id: user.id, fullName: user.fullName, email: user.email },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Щось пішло не так' });
  }
});

app.get('/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
      select: { id: true, fullName: true, email: true, createdAt: true },
    });

    if (!user) {
      return res.status(404).json({ error: 'Користувача не знайдено' });
    }

    res.json({ user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Щось пішло не так' });
  }
});

app.post('/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) {
      return res.status(400).json({ error: 'Немає даних від Google' });
    }
    if (!process.env.GOOGLE_CLIENT_ID) {
      return res.status(500).json({ error: 'Google-вхід не налаштовано на сервері' });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (!payload || !payload.email || !payload.email_verified) {
      return res.status(401).json({ error: 'Google не підтвердив email' });
    }

    let user = await prisma.user.findUnique({ where: { email: payload.email } });
    if (!user) {
      // Для входу через Google пароль не потрібен — зберігаємо випадковий, якого ніхто не знає
      const randomPassword = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 10);
      user = await prisma.user.create({
        data: { fullName: payload.name || payload.email, email: payload.email, password: randomPassword },
      });
    }

    res.json({
      token: makeToken(user.id),
      user: { id: user.id, fullName: user.fullName, email: user.email },
    });
  } catch (error) {
    console.error(error);
    res.status(401).json({ error: 'Не вдалось увійти через Google' });
  }
});

app.put('/auth/me', authMiddleware, async (req, res) => {
  try {
    const { fullName } = req.body;
    if (!fullName || !fullName.trim()) {
      return res.status(400).json({ error: 'Вкажи ім\'я' });
    }
    const user = await prisma.user.update({
      where: { id: req.userId },
      data: { fullName: fullName.trim() },
      select: { id: true, fullName: true, email: true, createdAt: true },
    });
    res.json({ user });
  } catch (error) {
    sendServerError(res, error);
  }
});

// --- Калібрування та чутливість трекінгу (діє у всіх режимах) ---

app.get('/settings', authMiddleware, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.userId },
      select: { calibration: true },
    });
    res.json({ calibration: user?.calibration || null });
  } catch (error) {
    sendServerError(res, error);
  }
});

app.put('/settings', authMiddleware, async (req, res) => {
  try {
    const { calibration } = req.body;
    if (!calibration || typeof calibration !== 'object') {
      return res.status(400).json({ error: 'Некоректні налаштування' });
    }
    await prisma.user.update({
      where: { id: req.userId },
      data: { calibration },
    });
    res.json({ calibration });
  } catch (error) {
    sendServerError(res, error);
  }
});

app.get('/presets', authMiddleware, async (req, res) => {
  try {
    const presets = await prisma.preset.findMany({
      where: { userId: req.userId },
      orderBy: { createdAt: 'desc' },
    });
    res.json({ presets });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Щось пішло не так' });
  }
});

app.post('/presets', authMiddleware, async (req, res) => {
  try {
    const { name, soundType, settings } = req.body;

    if (!name || !soundType) {
      return res.status(400).json({ error: 'Вкажи назву і тип звуку' });
    }

    const preset = await prisma.preset.create({
      data: {
        name,
        soundType,
        settings: settings || {},
        userId: req.userId,
      },
    });

    res.json({ preset });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Щось пішло не так' });
  }
});

app.put('/presets/:id', authMiddleware, async (req, res) => {
  try {
    const presetId = parseInt(req.params.id);
    const preset = await prisma.preset.findUnique({ where: { id: presetId } });

    if (!preset) {
      return res.status(404).json({ error: 'Пресет не знайдено' });
    }
    if (preset.userId !== req.userId) {
      return res.status(403).json({ error: 'Це не твій пресет' });
    }

    const { name, soundType, settings, favorite } = req.body;
    const updated = await prisma.preset.update({
      where: { id: presetId },
      data: {
        ...(name !== undefined && { name }),
        ...(soundType !== undefined && { soundType }),
        ...(settings !== undefined && { settings }),
        ...(favorite !== undefined && { favorite: !!favorite }),
      },
    });
    res.json({ preset: updated });
  } catch (error) {
    sendServerError(res, error);
  }
});

app.post('/presets/:id/use', authMiddleware, async (req, res) => {
  try {
    const presetId = parseInt(req.params.id);
    const preset = await prisma.preset.findUnique({ where: { id: presetId } });

    if (!preset) {
      return res.status(404).json({ error: 'Пресет не знайдено' });
    }
    if (preset.userId !== req.userId) {
      return res.status(403).json({ error: 'Це не твій пресет' });
    }

    const updated = await prisma.preset.update({
      where: { id: presetId },
      data: { usedCount: { increment: 1 } },
    });
    res.json({ preset: updated });
  } catch (error) {
    sendServerError(res, error);
  }
});

app.delete('/presets/:id', authMiddleware, async (req, res) => {
  try {
    const presetId = parseInt(req.params.id);

    const preset = await prisma.preset.findUnique({ where: { id: presetId } });

    if (!preset) {
      return res.status(404).json({ error: 'Пресет не знайдено' });
    }

    if (preset.userId !== req.userId) {
      return res.status(403).json({ error: 'Це не твій пресет' });
    }

    await prisma.preset.delete({ where: { id: presetId } });

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Щось пішло не так' });
  }
});

// --- Записи ---

app.get('/recordings', authMiddleware, async (req, res) => {
  try {
    const recordings = await prisma.recording.findMany({
      where: { userId: req.userId },
      orderBy: { createdAt: 'desc' },
    });
    res.json({ recordings });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Щось пішло не так' });
  }
});

app.post('/recordings', authMiddleware, handleSoundUpload, async (req, res) => {
  try {
    const { name, mode, durationSec } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: 'Файл не завантажено' });
    }

    const duration = parseInt(durationSec);

    const recording = await prisma.recording.create({
      data: {
        name: name || 'Без назви',
        fileName: req.file.filename,
        mode: mode || null,
        durationSec: Number.isFinite(duration) ? duration : null,
        sizeBytes: req.file.size,
        userId: req.userId,
      },
    });

    res.json({ recording });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Щось пішло не так' });
  }
});

app.put('/recordings/:id', authMiddleware, async (req, res) => {
  try {
    const recordingId = parseInt(req.params.id);
    const recording = await prisma.recording.findUnique({ where: { id: recordingId } });

    if (!recording) {
      return res.status(404).json({ error: 'Запис не знайдено' });
    }
    if (recording.userId !== req.userId) {
      return res.status(403).json({ error: 'Це не твій запис' });
    }

    const { name } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Вкажи назву' });
    }

    const updated = await prisma.recording.update({
      where: { id: recordingId },
      data: { name: name.trim() },
    });
    res.json({ recording: updated });
  } catch (error) {
    sendServerError(res, error);
  }
});

app.delete('/recordings/:id', authMiddleware, async (req, res) => {
  try {
    const recordingId = parseInt(req.params.id);

    const recording = await prisma.recording.findUnique({ where: { id: recordingId } });

    if (!recording) {
      return res.status(404).json({ error: 'Запис не знайдено' });
    }

    if (recording.userId !== req.userId) {
      return res.status(403).json({ error: 'Це не твій запис' });
    }

    const filePath = path.join(__dirname, 'uploads', recording.fileName);
    fs.unlink(filePath, (err) => {
      if (err) console.error('Не вдалось видалити файл', err);
    });

    await prisma.recording.delete({ where: { id: recordingId } });

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Щось пішло не так' });
  }
});

// --- Власні звуки (семпли для інструмента і фонові петлі) ---

app.get('/sounds', authMiddleware, async (req, res) => {
  try {
    const { type } = req.query;
    const where = { userId: req.userId };
    if (type) where.type = type;

    const sounds = await prisma.sound.findMany({
      where,
      orderBy: { createdAt: 'desc' },
    });
    res.json({ sounds });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Щось пішло не так' });
  }
});

app.post('/sounds', authMiddleware, handleSoundUpload, async (req, res) => {
  try {
    const { name, type } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: 'Файл не завантажено' });
    }
    if (!type || !['instrument', 'background'].includes(type)) {
      return res.status(400).json({ error: 'Вкажи коректний тип звуку' });
    }

    const sound = await prisma.sound.create({
      data: {
        name: name || 'Без назви',
        fileName: req.file.filename,
        type,
        userId: req.userId,
      },
    });

    res.json({ sound });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Щось пішло не так' });
  }
});

// --- Бібліотека Freesound (ключ лежить тільки в змінній оточення FREESOUND_API_KEY) ---

const FS_BASE = 'https://freesound.org/apiv2';
const fsPreviewCache = new Map(); // id -> { url, at }

function fsKey() {
  return process.env.FREESOUND_API_KEY || '';
}

app.get('/freesound/search', authMiddleware, async (req, res) => {
  try {
    if (!fsKey()) return res.status(503).json({ error: 'Бібліотека звуків не налаштована на сервері' });
    const q = String(req.query.q || '').trim();
    if (!q) return res.json({ results: [], count: 0 });
    const page = Math.max(1, parseInt(req.query.page) || 1);

    const params = new URLSearchParams({
      query: q,
      page: String(page),
      page_size: '15',
      fields: 'id,name,username,license,duration,previews,url',
      filter: 'duration:[0.1 TO 30] license:("Creative Commons 0" OR "Attribution")',
      sort: 'score',
      token: fsKey(),
    });
    const r = await fetch(`${FS_BASE}/search/text/?${params}`);
    if (!r.ok) {
      console.error('Freesound search', r.status, await r.text());
      return res.status(502).json({ error: 'Freesound зараз недоступний' });
    }
    const data = await r.json();
    const results = (data.results || []).map((x) => ({
      id: x.id,
      name: x.name,
      author: x.username,
      license: x.license,
      duration: x.duration,
      previewUrl: x.previews && (x.previews['preview-lq-mp3'] || x.previews['preview-hq-mp3']),
      url: x.url,
    }));
    res.json({ results, count: data.count || 0, hasMore: !!data.next });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Щось пішло не так' });
  }
});

// Публічний (бо <audio> не вміє слати токен): віддає прев'ю-mp3 звуку з Freesound
app.get('/freesound/preview/:id', async (req, res) => {
  try {
    if (!fsKey()) return res.status(503).end();
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).end();

    let cached = fsPreviewCache.get(id);
    if (!cached) {
      const r = await fetch(`${FS_BASE}/sounds/${id}/?fields=previews&token=${fsKey()}`);
      if (!r.ok) return res.status(404).end();
      const d = await r.json();
      const url = d.previews && (d.previews['preview-hq-mp3'] || d.previews['preview-lq-mp3']);
      if (!url) return res.status(404).end();
      cached = { url };
      fsPreviewCache.set(id, cached);
    }
    const audio = await fetch(cached.url);
    if (!audio.ok) return res.status(502).end();
    res.set('Content-Type', 'audio/mpeg');
    res.set('Cache-Control', 'public, max-age=86400');
    res.send(Buffer.from(await audio.arrayBuffer()));
  } catch (error) {
    console.error(error);
    res.status(500).end();
  }
});

app.post('/sounds/freesound', authMiddleware, async (req, res) => {
  try {
    const { freesoundId, name, type, author, license, sourceUrl } = req.body;
    const fid = parseInt(freesoundId);
    if (!fid) return res.status(400).json({ error: 'Невірний звук' });
    if (!type || !['instrument', 'background'].includes(type)) {
      return res.status(400).json({ error: 'Вкажи коректний тип звуку' });
    }
    const sound = await prisma.sound.create({
      data: {
        name: String(name || 'Без назви').slice(0, 120),
        fileName: `fs:${fid}`,
        type,
        author: author ? String(author).slice(0, 120) : null,
        license: license ? String(license).slice(0, 120) : null,
        sourceUrl: sourceUrl ? String(sourceUrl).slice(0, 300) : null,
        userId: req.userId,
      },
    });
    res.json({ sound });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Щось пішло не так' });
  }
});

app.delete('/sounds/:id', authMiddleware, async (req, res) => {
  try {
    const soundId = parseInt(req.params.id);

    const sound = await prisma.sound.findUnique({ where: { id: soundId } });

    if (!sound) {
      return res.status(404).json({ error: 'Звук не знайдено' });
    }
    if (sound.userId !== req.userId) {
      return res.status(403).json({ error: 'Це не твій звук' });
    }

    if (!sound.fileName.startsWith('fs:')) {
      const filePath = path.join(__dirname, 'uploads', sound.fileName);
      fs.unlink(filePath, (err) => {
        if (err) console.error('Не вдалось видалити файл', err);
      });
    }

    await prisma.sound.delete({ where: { id: soundId } });

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Щось пішло не так' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Сервер запущено на http://localhost:${PORT}`);
});