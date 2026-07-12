const express = require('express');
const morgan = require('morgan');
const path = require('path');
const { analyzeLog } = require('./lib/logAnalyzer');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(morgan('dev'));
app.use(express.json({ limit: '4mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/api/health', (req, res) => {
  res.json({ ok: true, runtime: `node ${process.version}` });
});

app.post('/api/analyze', (req, res) => {
  const { log } = req.body || {};
  if (!log || !String(log).trim()) return res.status(400).json({ error: 'Provide a non-empty "log" field.' });
  try {
    res.json(analyzeLog(log));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/*', (req, res) => res.status(404).json({ error: 'Not found' }));

app.listen(PORT, () => console.log(`[log-triage] listening on ${PORT}`));

module.exports = app;
