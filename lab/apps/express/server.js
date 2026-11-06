// Express lab app implementing the Labyrinth lab contract (see lab/README.md).
const express = require('express');
const multer = require('multer');
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
const sessions = new Map();
const items = [{ id: 1, name: 'Widget' }, { id: 2, name: 'Gadget' }];
const cookie = (req, name) => (req.headers.cookie || '').split(';').map(s => s.trim().split('=')).find(([k]) => k === name)?.[1];
const user = req => sessions.get(cookie(req, 'sid'));

app.get('/api/health', (req, res) => res.json({ ok: true, framework: 'express' }));
app.get('/api/items', (req, res) => res.json(items));
app.get('/api/items/:id', (req, res) => {
  const it = items.find(i => String(i.id) === req.params.id);
  it ? res.json(it) : res.status(404).json({ error: 'not found' });
});
app.post('/api/items', (req, res) => res.status(201).json({ id: 3, ...req.body }));
app.get('/login', (req, res) => res.send('<form method="post" action="/login"><input name="username"><input name="password" type="password"><button>Sign in</button></form>'));
app.post('/login', (req, res) => {
  if (req.body.username === 'alice' && req.body.password === 'wonderland') {
    const sid = crypto.randomBytes(16).toString('hex');
    sessions.set(sid, 'alice');
    res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax' });
    res.cookie('theme', 'dark');
    return res.redirect(302, '/dashboard');
  }
  res.status(401).send('invalid credentials');
});
app.get('/dashboard', (req, res) => user(req) ? res.send(`<h1>Welcome ${user(req)}</h1>`) : res.redirect(302, '/login'));
app.post('/checkout', (req, res) => user(req) ? res.json({ ok: true, order: 1001 }) : res.status(401).json({ error: 'login required' }));
app.post('/upload', multer({ storage: multer.memoryStorage() }).single('file'), (req, res) => res.json({ size: req.file ? req.file.size : 0 }));
app.get('/redirect', (req, res) => res.redirect(302, '/api/health'));
app.get('/stream', (req, res) => {
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
  let n = 0;
  const t = setInterval(() => { res.write(`data: tick ${++n}\n\n`); if (n === 3) { clearInterval(t); res.end(); } }, 500);
});

const server = http.createServer(app);
new WebSocketServer({ server, path: '/ws' }).on('connection', ws => ws.on('message', m => ws.send('echo:' + m)));
server.listen(process.env.PORT || 8000, () => console.log('express lab app on', process.env.PORT || 8000));
