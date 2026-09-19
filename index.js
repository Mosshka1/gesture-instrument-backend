const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { PrismaClient } = require('@prisma/client');
require('dotenv').config();
const authMiddleware = require('./middleware/auth');

const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

const upload = multer({ dest: 'uploads/' });

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

app.post('/recordings', authMiddleware, upload.single('audio'), async (req, res) => {
  try {
    const { name } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: 'Файл не завантажено' });
    }

    const recording = await prisma.recording.create({
      data: {
        name: name || 'Без назви',
        fileName: req.file.filename,
        userId: req.userId,
      },
    });

    res.json({ recording });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Щось пішло не так' });
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

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Сервер запущено на http://localhost:${PORT}`);
});