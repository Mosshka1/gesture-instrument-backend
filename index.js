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

    const filePath = path.join(__dirname, 'uploads', sound.fileName);
    fs.unlink(filePath, (err) => {
      if (err) console.error('Не вдалось видалити файл', err);
    });

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