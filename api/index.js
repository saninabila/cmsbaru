const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());

// Inisialisasi Firebase Admin SDK
// Di Vercel, kredensial bisa dimasukkan via Environment Variables
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      // Menangani newline pada private key di environment variable
      privateKey: process.env.FIREBASE_PRIVATE_KEY
        ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
        : undefined,
    }),
  });
}

const db = admin.firestore();

// ===== Autentikasi Admin =====
// Password admin disimpan di environment variable ADMIN_PASSWORD.
// Token sesi bersifat stateless (HMAC), sehingga tetap valid di Vercel.

const COOKIE_NAME = 'admin_token';

function getAdminPassword() {
  return process.env.ADMIN_PASSWORD;
}

function createSessionToken() {
  const payload = 'admin-session-v1';
  return crypto
    .createHmac('sha256', getAdminPassword())
    .update(payload)
    .digest('hex');
}

function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return false;
  const expected = createSessionToken();
  const a = Buffer.from(token);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function parseCookies(req) {
  const header = req.headers.cookie;
  const cookies = {};
  if (!header) return cookies;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i === -1) continue;
    cookies[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return cookies;
}

// Middleware: verifikasi token admin dari cookie
function requireAdmin(req, res, next) {
  const token = parseCookies(req)[COOKIE_NAME];
  if (!verifySessionToken(token)) {
    return res.status(401).json({ error: 'Unauthorized: login admin diperlukan.' });
  }
  next();
}

app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body || {};
  const adminPassword = getAdminPassword();

  if (!adminPassword) {
    return res.status(503).json({ error: 'ADMIN_PASSWORD belum diatur di environment variables.' });
  }

  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Password wajib diisi.' });
  }

  const a = Buffer.from(password);
  const b = Buffer.from(adminPassword);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'Password salah.' });
  }

  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${createSessionToken()}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800`);
  res.json({ ok: true });
});

app.post('/api/admin/logout', (req, res) => {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0`);
  res.json({ ok: true });
});

app.get('/api/admin/session', (req, res) => {
  const token = parseCookies(req)[COOKIE_NAME];
  res.json({ authenticated: verifySessionToken(token) });
});

// ===== API Publik (hanya postingan berstatus "published") =====

app.get('/api/posts', async (req, res) => {
  try {
    const snapshot = await db.collection('posts').get();
    const posts = snapshot.docs
      .map(doc => ({ id: doc.id, ...doc.data() }))
      .filter(post => post.status === 'published')
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.status(200).json(posts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/posts/:id', async (req, res) => {
  try {
    const doc = await db.collection('posts').doc(req.params.id).get();
    if (!doc.exists) {
      return res.status(404).json({ error: 'Postingan tidak ditemukan.' });
    }
    const post = { id: doc.id, ...doc.data() };
    // Draft tidak boleh terlihat dari area publik
    if (post.status !== 'published') {
      return res.status(404).json({ error: 'Postingan tidak ditemukan.' });
    }
    res.status(200).json(post);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== API Hero Section =====

function sanitizeHeroSlides(slides) {
  if (!Array.isArray(slides)) return [];
  return slides
    .slice(0, 3)
    .map(s => (s && typeof s === 'object') ? s : {})
    .map(s => {
      const title = typeof s.title === 'string' ? s.title.trim() : '';
      if (!title) return null;
      return {
        kicker: typeof s.kicker === 'string' && s.kicker.trim() ? s.kicker.trim() : 'Sorotan',
        title,
        sub: typeof s.sub === 'string' ? s.sub.trim() : '',
        cta: typeof s.cta === 'string' && s.cta.trim() ? s.cta.trim() : 'Baca selengkapnya',
        link: typeof s.link === 'string' && s.link.trim() ? s.link.trim() : '#postingan',
      };
    })
    .filter(Boolean);
}

// Publik: slide hero hasil aturan admin (kosong = fallback otomatis)
app.get('/api/hero', async (req, res) => {
  try {
    const doc = await db.collection('settings').doc('hero').get();
    const slides = doc.exists && Array.isArray(doc.data().slides) ? doc.data().slides : [];
    res.status(200).json({ slides });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== API Admin (membutuhkan login) =====

app.get('/api/admin/hero', requireAdmin, async (req, res) => {
  try {
    const doc = await db.collection('settings').doc('hero').get();
    const slides = doc.exists && Array.isArray(doc.data().slides) ? doc.data().slides : [];
    res.status(200).json({ slides });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/hero', requireAdmin, async (req, res) => {
  const slides = sanitizeHeroSlides((req.body || {}).slides);
  try {
    await db.collection('settings').doc('hero').set({
      slides,
      updatedAt: new Date().toISOString(),
    });
    res.status(200).json({ slides });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/posts', requireAdmin, async (req, res) => {
  try {
    const snapshot = await db.collection('posts').get();
    const posts = snapshot.docs
      .map(doc => ({ id: doc.id, ...doc.data() }))
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.status(200).json(posts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

function sanitizePostInput(body) {
  const title = typeof body.title === 'string' ? body.title.trim() : '';
  const content = typeof body.content === 'string' ? body.content.trim() : '';
  const status = body.status === 'published' ? 'published' : 'draft';

  if (!title) return { error: 'Judul wajib diisi.' };
  if (!content) return { error: 'Konten wajib diisi.' };

  return { value: { title, content, status } };
}

app.post('/api/admin/posts', requireAdmin, async (req, res) => {
  const result = sanitizePostInput(req.body || {});
  if (result.error) {
    return res.status(400).json({ error: result.error });
  }
  const now = new Date().toISOString();
  const newPost = { ...result.value, createdAt: now, updatedAt: now };
  try {
    const docRef = await db.collection('posts').add(newPost);
    res.status(201).json({ id: docRef.id, ...newPost });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/posts/:id', requireAdmin, async (req, res) => {
  const result = sanitizePostInput(req.body || {});
  if (result.error) {
    return res.status(400).json({ error: result.error });
  }
  try {
    const docRef = db.collection('posts').doc(req.params.id);
    const doc = await docRef.get();
    if (!doc.exists) {
      return res.status(404).json({ error: 'Postingan tidak ditemukan.' });
    }
    const updates = { ...result.value, updatedAt: new Date().toISOString() };
    await docRef.update(updates);
    res.status(200).json({ id: doc.id, ...doc.data(), ...updates });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/posts/:id', requireAdmin, async (req, res) => {
  try {
    await db.collection('posts').doc(req.params.id).delete();
    res.status(200).json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== Penyajian halaman statis =====
// Area publik: /  (public/index.html, public/post.html)
// Area admin : /admin (public/admin/index.html)
app.use(express.static(path.join(__dirname, '../public')));

// Mudah diakses: /admin -> public/admin/index.html
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/admin/index.html'));
});

// Export untuk Vercel Serverless Function
module.exports = app;

// Jalankan server lokal jika tidak di Vercel
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server CMS berjalan di http://localhost:${PORT}`);
    console.log(`Area publik: http://localhost:${PORT}/`);
    console.log(`Area admin : http://localhost:${PORT}/admin`);
  });
}
