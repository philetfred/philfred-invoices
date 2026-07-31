const express = require('express');
const fetch = require('node-fetch');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const app = express();

// ─── Body parsers ─────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  if (req.path === '/api/webhook-qb') {
    express.raw({ type: '*/*' })(req, res, next);
  } else {
    express.json()(req, res, next);
  }
});

// ─── Simple cookie parser ───────────────────────────────────────────────────
app.use((req, res, next) => {
  req.cookies = {};
  const header = req.headers.cookie;
  if (header) {
    header.split(';').forEach(pair => {
      const idx = pair.indexOf('=');
      if (idx > -1) {
        const key = pair.slice(0, idx).trim();
        const val = pair.slice(idx + 1).trim();
        req.cookies[key] = decodeURIComponent(val);
      }
    });
  }
  next();
});

app.use(express.static(path.join(__dirname)));

const MONGODB_URI = process.env.MONGODB_URI;
let db = null;

const defaultAppUsers = [
  { username: 'Fred',  passwordHash: '7d301c9cefaf53d6f7b43a7cb228e18f8466c62f62fe87aaf621132eba509bb0', role: 'admin' },
  { username: 'AlexB', passwordHash: 'f5286a7722c969aee390525c7309e98864bd9057b6983c600469b80d31ad4997', role: 'employe' },
  { username: 'Alex',  passwordHash: '9b5e34a4f2d715c4ea89842da98bbeae766851584b1e746457f3b1b887d3d9be', role: 'employe' },
  { username: 'MathA', passwordHash: 'fcf5077d5abff23bae284cdda0f2533a5d5860a9d2442943f78b603755e92bc5', role: 'employe' },
];

async function connectMongo() {
  if (!MONGODB_URI) { console.log('No MONGODB_URI set'); return; }
  try {
    const client = new MongoClient(MONGODB_URI, { tls: true, tlsAllowInvalidCertificates: true, serverSelectionTimeoutMS: 10000 });
    await client.connect();
    db = client.db('philfred');
    console.log('Connected to MongoDB');
    const count = await db.collection('priceRules').countDocuments();
    if (count === 0) { await db.collection('priceRules').insertMany(defaultPriceRules); console.log('Price rules initialized'); }
    const userCount = await db.collection('appUsers').countDocuments();
    if (userCount === 0) { await db.collection('appUsers').insertMany(defaultAppUsers); console.log('App users initialized'); }
    await db.collection('appSessions').createIndex({ sessionId: 1 });
    await db.collection('appUsers').createIndex({ username: 1 });
    await db.collection('webhookProcessedInvoices').createIndex({ realmId: 1, invoiceId: 1 }, { unique: true });
  } catch(err) { console.error('MongoDB connection error:', err); }
}

function getOrCreateSessionId(req, res) {
  let sessionId = req.cookies.sessionId;
  if (!sessionId) {
    sessionId = crypto.randomBytes(24).toString('hex');
    res.setHeader('Set-Cookie', `sessionId=${sessionId}; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax`);
  }
  return sessionId;
}

async function saveSessionToken(sessionId, tokenData) {
  if (db) {
    await db.collection('sessions').updateOne({ sessionId }, { $set: { ...tokenData, sessionId, updatedAt: new Date() } }, { upsert: true });
  } else { memorySessions[sessionId] = tokenData; }
}

async function getSessionToken(sessionId) {
  if (db) return await db.collection('sessions').findOne({ sessionId });
  return memorySessions[sessionId] || null;
}

const memorySessions = {};
const CLIENT_ID = process.env.QB_CLIENT_ID;
const CLIENT_SECRET = process.env.QB_CLIENT_SECRET;
const REDIRECT_URI = process.env.QB_REDIRECT_URI || 'https://philfred-invoices.onrender.com/callback';

app.get('/auth', (req, res) => {
  const sessionId = getOrCreateSessionId(req, res);
  const scope = 'com.intuit.quickbooks.accounting';
  const state = sessionId + '.' + Math.random().toString(36).substring(7);
  const authUrl = `https://appcenter.intuit.com/connect/oauth2?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=${scope}&state=${state}&prompt=select_account`;
  res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
  const { code, realmId, state } = req.query;
  if (!code) return res.status(400).send('No code received');
  let sessionId = state ? state.split('.')[0] : null;
  if (!sessionId || sessionId.length !== 48) { sessionId = getOrCreateSessionId(req, res); }
  else { res.setHeader('Set-Cookie', `sessionId=${sessionId}; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax`); }
  try {
    const credentials = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    const response = await fetch('https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer', {
      method: 'POST',
      headers: { 'Authorization': 'Basic ' + credentials, 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`
    });
    const data = await response.json();
    if (data.access_token) {
      await saveSessionToken(sessionId, { accessToken: data.access_token, refreshToken: data.refresh_token, realmId, expiresAt: Date.now() + (data.expires_in * 1000) });
      console.log('QB OAuth: nouvelle connexion, realmId =', realmId);
      res.redirect('/?connected=true');
    } else { console.error('QB OAuth: échec auth_failed', data); res.redirect('/?error=auth_failed'); }
  } catch (err) { console.error('QB OAuth callback erreur:', err); res.redirect('/?error=' + err.message); }
});

async function getValidToken(req, res) {
  const sessionId = getOrCreateSessionId(req, res);
  const session = await getSessionToken(sessionId);
  if (!session || !session.accessToken) throw new Error('Not authenticated');
  if (Date.now() > session.expiresAt - 300000) {
    const credentials = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    const response = await fetch('https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer', {
      method: 'POST',
      headers: { 'Authorization': 'Basic ' + credentials, 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: `grant_type=refresh_token&refresh_token=${session.refreshToken}`
    });
    const data = await response.json();
    if (data.access_token) {
      session.accessToken = data.access_token; session.refreshToken = data.refresh_token;
      session.expiresAt = Date.now() + (data.expires_in * 1000);
      await saveSessionToken(sessionId, session);
    } else {
      await saveSessionToken(sessionId, { accessToken: null, refreshToken: null, realmId: null, expiresAt: null });
      throw new Error('Token refresh failed - please reconnect');
    }
  }
  return { token: session.accessToken, realmId: session.realmId };
}

// ─── Récupère un token valide, de préférence pour le realmId demandé ───────
// (utilisé par le webhook, qui n'a pas de cookie de session).
// Corrigé: on ne prend plus "n'importe quelle" session — on filtre d'abord
// par realmId pour éviter d'utiliser un token appartenant à une autre
// compagnie QuickBooks (ce qui ferait échouer silencieusement l'appel API).
async function getAnyValidToken(preferredRealmId) {
  if (!db) throw new Error('DB non connectée');
  const query = { accessToken: { $ne: null } };
  if (preferredRealmId) query.realmId = preferredRealmId;
  let session = await db.collection('sessions').findOne(query, { sort: { updatedAt: -1 } });
  if (!session && preferredRealmId) {
    console.warn('getAnyValidToken: aucune session trouvée pour realmId =', preferredRealmId, '— on retente sans filtre realmId (à corriger: reconnecter QuickBooks sur ce realm).');
    session = await db.collection('sessions').findOne({ accessToken: { $ne: null } }, { sort: { updatedAt: -1 } });
  }
  if (!session || !session.accessToken) throw new Error('Aucune session QB active (as-tu cliqué "Connecter QuickBooks" au moins une fois ?)');
  if (preferredRealmId && session.realmId && session.realmId !== preferredRealmId) {
    console.warn('getAnyValidToken: la session trouvée (realmId=' + session.realmId + ') ne correspond pas au realmId du webhook (' + preferredRealmId + ').');
  }
  if (Date.now() > session.expiresAt - 300000) {
    const credentials = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    const response = await fetch('https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer', {
      method: 'POST',
      headers: { 'Authorization': 'Basic ' + credentials, 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: `grant_type=refresh_token&refresh_token=${session.refreshToken}`
    });
    const data = await response.json();
    if (data.access_token) {
      await db.collection('sessions').updateOne({ sessionId: session.sessionId },
        { $set: { accessToken: data.access_token, refreshToken: data.refresh_token, expiresAt: Date.now() + (data.expires_in * 1000), updatedAt: new Date() } });
      return { token: data.access_token, realmId: session.realmId };
    } else { throw new Error('Token refresh failed'); }
  }
  return { token: session.accessToken, realmId: session.realmId };
}

let qbProducts = [];
let qbProductsLoadedAt = 0;

// Recharge la liste des produits QB. Appelée au premier webhook, puis
// automatiquement re-rafraîchie si un item reçu du webhook n'est pas trouvé
// dans le cache (ex: nouveau produit créé dans QB après le dernier chargement).
async function loadQbProducts(realmId, token) {
  const prodData = await (await fetch(`https://quickbooks.api.intuit.com/v3/company/${realmId}/query?query=SELECT * FROM Item WHERE Active=true MAXRESULTS 200&minorversion=65`, { headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'application/json' } })).json();
  qbProducts = (prodData.QueryResponse?.Item || []).filter(i => ['Service','Inventory','NonInventory'].includes(i.Type));
  qbProductsLoadedAt = Date.now();
  console.log('Webhook QB: cache produits rechargé (' + qbProducts.length + ' items)');
}

app.get('/api/customer/:id', async (req, res) => {
  try {
    const { token, realmId } = await getValidToken(req, res);
    const response = await fetch(`https://quickbooks.api.intuit.com/v3/company/${realmId}/customer/${req.params.id}?minorversion=65`, { headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'application/json' } });
    res.json(await response.json());
  } catch (err) { res.status(401).json({ error: err.message }); }
});

const defaultPriceRules = [
  { name: 'IGA extra Super Marché Famille Primeau inc. Beauharnois', type: 'percent', value: -20 },
  { name: 'IGA extra Super Marché Primeau et fils inc.', type: 'percent', value: -20 },
  { name: 'IGA extra Gladu (2747-6761 Québec Inc.)', type: 'percent', value: -22 },
  { name: 'IGA Extra Laprairie', type: 'percent', value: -22 },
  { name: 'IGA extra Les Marchés Lambert Chambly', type: 'percent', value: -22 },
  { name: 'IGA extra Les Marchés Lambert Richelieu', type: 'percent', value: -22 },
  { name: 'IGA extra Yan Gladu Douglas (9425-6211 Qc Inc.)', type: 'percent', value: -22 },
  { name: 'IGA Gladu Saint-Luc (9425-6260 Qc Inc.)', type: 'percent', value: -22 },
  { name: 'IGA Groupe Pro 40 inc.', type: 'percent', value: -22 },
  { name: 'IGA Supermarché Laplante inc.', type: 'percent', value: -22 },
  { name: 'IGA Candiac Sobeys Capital Inc', type: 'percent', value: -22 },
  { name: 'Dépanneur Conrad-Gosselin Inc.', type: 'percent', value: -25 },
  { name: 'Dépanneur Grimard - Richelieu (9070-9783 Qc Inc.)', type: 'percent', value: -25 },
  { name: 'Dépanneur Lionel-Boulet Inc.', type: 'percent', value: -25 },
  { name: 'Dépanneur Marieville BSG Inc.', type: 'percent', value: -25 },
  { name: 'Marché 365 (2435-7147 Qc Inc.)', type: 'percent', value: -25 },
  { name: 'Marché Dessaulles', type: 'percent', value: -25 },
  { name: 'Marché Venise', type: 'percent', value: -25 },
  { name: 'Metro Gaz', type: 'percent', value: -25 },
  { name: 'Mon Petit Comptoir (Metro Bigras)', type: 'percent', value: -25 },
  { name: '2950-6680 Qc Inc. (Shell Boulevard Saint-Luc )', type: 'percent', value: -25 },
  { name: 'Depanneur Plus', type: 'percent', value: -25 },
  { name: 'IGA extra Châteauguay', type: 'percent', value: -25 },
  { name: 'IGA extra Famille Reid-Boursier inc.', type: 'percent', value: -25 },
  { name: "IGA extra Marché d'alimentation Beck inc.", type: "percent", value: -25 },
  { name: 'IGA extra Marché St-Pierre et Fils', type: 'percent', value: -25 },
  { name: 'La Maraîchère', type: 'percent', value: -25 },
  { name: 'Les Marchés Pépin Inc.', type: 'percent', value: -25 },
  { name: 'Les marchés Valérie et Martin Varennes', type: 'percent', value: -25 },
  { name: 'Marche Emily Philip Desmarais inc.', type: 'percent', value: -25 },
  { name: 'IGA - Famille Leblanc, Forté & fils', type: 'percent', value: -25 },
  { name: 'IGA Atwater', type: 'percent', value: -25 },
  { name: 'IGA Barcelo Molson', type: 'percent', value: -25 },
  { name: 'IGA Extra Supermarché Gilles Bariteau', type: 'percent', value: -25 },
  { name: 'IGA Famille Jodoin - 9026-4979 QUÉBEC INC.', type: 'percent', value: -25 },
  { name: 'IGA Famille Jodoin Douville - 9165-1588 QUÉBEC INC.', type: 'percent', value: -25 },
  { name: 'IGA Marché H. Dauphinais inc', type: 'percent', value: -25 },
  { name: 'IGA Supermarché St-Henri', type: 'percent', value: -25 },
  { name: 'IGA Valérie et Martin Longueuil', type: 'percent', value: -25 },
  { name: 'Supermarché Famille Picard #8615', type: 'percent', value: -25 },
  { name: 'IGA extra Marché Vincent inc.', type: 'percent', value: -30 },
  { name: 'Pasquier Delson', type: 'percent', value: -30 },
  { name: 'Pasquier St-Jean-sur-Richelieu', type: 'percent', value: -30 },
  { name: 'super_c_pattern', type: 'pattern_fixed', value: -8, pattern: 'super c' }
];

let priceRules = [...defaultPriceRules];

app.get('/api/price-rules', async (req, res) => {
  try {
    if (db) { const rules = await db.collection('priceRules').find({}, { projection: { _id: 0 } }).toArray(); return res.json(rules); }
    res.json(priceRules);
  } catch(err) { res.json(priceRules); }
});

app.post('/api/price-rules', async (req, res) => {
  try {
    if (db) { await db.collection('priceRules').deleteMany({}); if (req.body.length > 0) await db.collection('priceRules').insertMany(req.body); }
    else { priceRules = req.body; }
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/price-rules/add', async (req, res) => {
  const rule = req.body;
  try {
    if (db) { await db.collection('priceRules').deleteOne({ name: new RegExp('^' + rule.name + '$', 'i') }); await db.collection('priceRules').insertOne(rule); }
    else { priceRules = priceRules.filter(r => r.name.toLowerCase() !== rule.name.toLowerCase()); priceRules.push(rule); }
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/price-rules/:index', async (req, res) => {
  const index = parseInt(req.params.index);
  try {
    if (db) { const rules = await db.collection('priceRules').find({}, { projection: { _id: 0 } }).toArray(); if (rules[index]) await db.collection('priceRules').deleteOne({ name: rules[index].name }); }
    else { priceRules.splice(index, 1); }
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/taxcodes', async (req, res) => {
  try {
    const { token, realmId } = await getValidToken(req, res);
    res.json(await (await fetch(`https://quickbooks.api.intuit.com/v3/company/${realmId}/query?query=SELECT * FROM TaxCode&minorversion=65`, { headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'application/json' } })).json());
  } catch (err) { res.status(401).json({ error: err.message }); }
});

app.get('/api/next-invoice-number', async (req, res) => {
  try {
    const { token, realmId } = await getValidToken(req, res);
    const headers = { 'Authorization': 'Bearer ' + token, 'Accept': 'application/json' };
    const base = `https://quickbooks.api.intuit.com/v3/company/${realmId}`;
    const [invRes, cmRes] = await Promise.all([
      fetch(`${base}/query?query=SELECT DocNumber FROM Invoice MAXRESULTS 100&minorversion=65`, { headers }),
      fetch(`${base}/query?query=SELECT DocNumber FROM CreditMemo MAXRESULTS 100&minorversion=65`, { headers })
    ]);
    const allDocs = [...((await invRes.json()).QueryResponse?.Invoice || []), ...((await cmRes.json()).QueryResponse?.CreditMemo || [])];
    let maxNum = 0;
    allDocs.forEach(doc => { if (doc.DocNumber) { const num = parseInt(doc.DocNumber.replace(/[^0-9]/g, '')); if (!isNaN(num) && num > maxNum) maxNum = num; } });
    res.json({ nextNumber: String(maxNum + 1) });
  } catch (err) { res.status(401).json({ error: err.message }); }
});

app.get('/api/status', async (req, res) => {
  const sessionId = getOrCreateSessionId(req, res);
  const session = await getSessionToken(sessionId);
  res.json({ connected: !!(session && session.accessToken), realmId: session ? session.realmId : null });
});

app.post('/api/qb', async (req, res) => {
  const { query } = req.body;
  try {
    const { token, realmId } = await getValidToken(req, res);
    res.json(await (await fetch(`https://quickbooks.api.intuit.com/v3/company/${realmId}/query?query=${encodeURIComponent(query)}&minorversion=65`, { headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'application/json' } })).json());
  } catch (err) { res.status(401).json({ error: err.message }); }
});

app.post('/api/qb-post', async (req, res) => {
  const { endpoint, body } = req.body;
  try {
    const { token, realmId } = await getValidToken(req, res);
    const response = await fetch(`https://quickbooks.api.intuit.com/v3/company/${realmId}/${endpoint}?minorversion=65`, {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    res.json(await response.json());
  } catch (err) { res.status(401).json({ error: err.message }); }
});

app.post('/api/parse-pdf', async (req, res) => {
  const { pdfBase64 } = req.body;
  if (!pdfBase64) return res.status(400).json({ error: 'Missing pdfBase64' });
  const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'ANTHROPIC_API_KEY not set on server' });
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 1000, messages: [{ role: 'user', content: [
        { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: pdfBase64 } },
        { type: 'text', text: '{"po_number":"...","supplier_name":"...","delivery_date":"YYYY-MM-DD","items":[{"description":"...","cases":4}]} Return only JSON.' }
      ]}]})
    });
    const data = await response.json();
    if (data.error) return res.status(500).json({ error: data.error.message });
    const text = data.content?.[0]?.text || '';
    let parsed;
    try { parsed = JSON.parse(text.trim()); } catch(e) { const m = text.match(/\{[\s\S]*\}/); if (m) parsed = JSON.parse(m[0]); else return res.status(500).json({ error: 'Parse error', raw: text }); }
    res.json(parsed);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

const crypto_builtin = require('crypto');
function hashPassword(p) { return crypto_builtin.createHash('sha256').update(p).digest('hex'); }

async function requireAppAuth(req, res, next) {
  const appSessionId = req.cookies.appSessionId;
  if (!appSessionId) return res.redirect('/login');
  if (db) { const session = await db.collection('appSessions').findOne({ sessionId: appSessionId }); if (!session) return res.redirect('/login'); req.appUser = session; }
  next();
}

async function requireAdmin(req, res, next) {
  const appSessionId = req.cookies.appSessionId;
  if (!appSessionId) return res.status(401).json({ error: 'Non authentifié' });
  if (db) { const session = await db.collection('appSessions').findOne({ sessionId: appSessionId }); if (!session || session.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' }); req.appUser = session; }
  next();
}

app.get('/login', (req, res) => { res.sendFile(path.join(__dirname, 'login.html')); });

app.post('/api/app-login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ success: false, error: 'Champs manquants' });
  try {
    const hash = hashPassword(password);
    let user = db ? await db.collection('appUsers').findOne({ username, passwordHash: hash }) : defaultAppUsers.find(u => u.username === username && u.passwordHash === hash);
    if (!user) return res.json({ success: false, error: "Nom d'utilisateur ou mot de passe incorrect" });
    const sessionId = crypto_builtin.randomBytes(24).toString('hex');
    if (db) await db.collection('appSessions').insertOne({ sessionId, username: user.username, role: user.role, createdAt: new Date() });
    res.setHeader('Set-Cookie', `appSessionId=${sessionId}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`);
    res.json({ success: true, role: user.role });
  } catch(e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/app-logout', async (req, res) => {
  const appSessionId = req.cookies.appSessionId;
  if (appSessionId && db) await db.collection('appSessions').deleteOne({ sessionId: appSessionId });
  res.setHeader('Set-Cookie', 'appSessionId=; HttpOnly; Path=/; Max-Age=0');
  res.json({ success: true });
});

app.get('/api/app-status', async (req, res) => {
  const appSessionId = req.cookies.appSessionId;
  if (!appSessionId) return res.json({ loggedIn: false });
  if (db) { const session = await db.collection('appSessions').findOne({ sessionId: appSessionId }); if (!session) return res.json({ loggedIn: false }); return res.json({ loggedIn: true, username: session.username, role: session.role }); }
  res.json({ loggedIn: false });
});

app.get('/api/app-users', requireAdmin, async (req, res) => {
  if (!db) return res.json([]);
  res.json(await db.collection('appUsers').find({}, { projection: { passwordHash: 0 } }).toArray());
});

app.post('/api/app-users/add', requireAdmin, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) return res.status(400).json({ error: 'Champs manquants' });
  if (db) { await db.collection('appUsers').deleteOne({ username }); await db.collection('appUsers').insertOne({ username, passwordHash: hashPassword(password), role }); }
  res.json({ success: true });
});

app.delete('/api/app-users/:username', requireAdmin, async (req, res) => {
  if (db) await db.collection('appUsers').deleteOne({ username: req.params.username });
  res.json({ success: true });
});

app.post('/api/app-users/edit', requireAdmin, async (req, res) => {
  const { originalUsername, newUsername, newPassword, newRole } = req.body;
  if (!originalUsername || !newUsername || !newRole) return res.status(400).json({ error: 'Champs manquants' });
  try {
    if (!db) return res.status(500).json({ error: 'DB non connectée' });
    const updateFields = { username: newUsername, role: newRole };
    if (newPassword && newPassword.trim() !== '') updateFields.passwordHash = hashPassword(newPassword);
    await db.collection('appUsers').updateOne({ username: originalUsername }, { $set: updateFields });
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.get('/', requireAppAuth, (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });
app.get('/admin', requireAdmin, (req, res) => { res.sendFile(path.join(__dirname, 'admin.html')); });
app.get('/import', requireAppAuth, (req, res) => { res.sendFile(path.join(__dirname, 'import.html')); });
app.get('/inventaire', requireAppAuth, (req, res) => { res.sendFile(path.join(__dirname, 'inventaire.html')); });
app.get('/production', requireAppAuth, (req, res) => { res.sendFile(path.join(__dirname, 'production.html')); });
app.get('/planning', requireAppAuth, (req, res) => { res.sendFile(path.join(__dirname, 'planning.html')); });

const INVENTORY_PRODUCTS = [
  'CAISSE 12x BAMBINO TOUTE GARNIE','CAISSE 8X MARGHERITA','CAISSE 8X MÉDITERRANÉENNE',
  'CAISSE 8x PEPPERONI-BACON','CAISSE 8x TOUTE GARNIE','CAISSE BOULE DE PÂTE (20x unités)',
  'PFPIZZ-AD','PFPIZZ-PEP','PFPIZZ-VEGE','PFPIZZA-MARG','PFPIZZFRO'
];

// Table de correspondance normalisée (minuscule + espaces compressés) pour
// matcher un nom d'item QuickBooks à un produit suivi, même si la casse ou
// les espaces diffèrent légèrement (ex: espace insécable, casse différente).
function normalizeName(s) { return (s || '').toLowerCase().trim().replace(/\s+/g, ' '); }
const NORMALIZED_INVENTORY_PRODUCTS = new Map(INVENTORY_PRODUCTS.map(name => [normalizeName(name), name]));
function matchInventoryProduct(qbItemName) {
  return NORMALIZED_INVENTORY_PRODUCTS.get(normalizeName(qbItemName)) || null;
}

app.get('/api/inventory', requireAppAuth, async (req, res) => {
  try {
    if (!db) return res.status(500).json({ error: 'DB non connectée' });
    const items = await db.collection('inventory').find({}, { projection: { _id: 0 } }).toArray();
    res.json(INVENTORY_PRODUCTS.map(name => { const f = items.find(i => i.name === name); return { name, stock: f ? f.stock : 0, threshold: f ? (f.threshold || 10) : 10 }; }));
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/inventory/add', requireAppAuth, async (req, res) => {
  const { name, qty, note } = req.body;
  if (!name || !qty || qty <= 0) return res.status(400).json({ error: 'Données invalides' });
  try {
    if (!db) return res.status(500).json({ error: 'DB non connectée' });
    await db.collection('inventory').updateOne({ name }, { $inc: { stock: qty }, $setOnInsert: { threshold: 10 } }, { upsert: true });
    await db.collection('productionLog').insertOne({ name, qty, note: note || '', type: 'production', createdAt: new Date(), createdBy: req.appUser?.username || 'unknown' });
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/inventory/deduct', requireAppAuth, async (req, res) => {
  const { name, qty, note } = req.body;
  if (!name || !qty || qty <= 0) return res.status(400).json({ error: 'Données invalides' });
  try {
    if (!db) return res.status(500).json({ error: 'DB non connectée' });
    await db.collection('inventory').updateOne({ name }, { $inc: { stock: -qty } }, { upsert: true });
    await db.collection('productionLog').insertOne({ name, qty: -qty, note: note || '', type: 'deduction', createdAt: new Date(), createdBy: req.appUser?.username || 'unknown' });
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/inventory/threshold', requireAdmin, async (req, res) => {
  const { name, threshold } = req.body;
  if (!name || threshold === undefined) return res.status(400).json({ error: 'Données invalides' });
  try {
    if (!db) return res.status(500).json({ error: 'DB non connectée' });
    await db.collection('inventory').updateOne({ name }, { $set: { threshold } }, { upsert: true });
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/inventory/log', requireAppAuth, async (req, res) => {
  try {
    if (!db) return res.status(500).json({ error: 'DB non connectée' });
    res.json(await db.collection('productionLog').find({}).sort({ createdAt: -1 }).limit(100).toArray());
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/planning', requireAppAuth, async (req, res) => {
  try {
    if (!db) return res.status(500).json({ error: 'DB non connectée' });
    const plans = await db.collection('deliveryPlans').find({}).sort({ deliveryDate: 1 }).toArray();
    res.json(plans.map(p => ({ ...p, _id: p._id.toString() })));
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/planning/add', requireAppAuth, async (req, res) => {
  const { clientName, deliveryDate, items } = req.body;
  if (!clientName || !deliveryDate || !items?.length) return res.status(400).json({ error: 'Données invalides' });
  try {
    if (!db) return res.status(500).json({ error: 'DB non connectée' });
    const result = await db.collection('deliveryPlans').insertOne({ clientName, deliveryDate, items, createdAt: new Date(), createdBy: req.appUser?.username || 'unknown' });
    res.json({ success: true, id: result.insertedId.toString() });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/planning/:id', requireAppAuth, async (req, res) => {
  try {
    if (!db) return res.status(500).json({ error: 'DB non connectée' });
    const { ObjectId } = require('mongodb');
    await db.collection('deliveryPlans').deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

const crypto_wb = require('crypto');

// ─── Webhook QuickBooks: déduit l'inventaire quand une facture est créée,
//     et le RESTAURE quand elle est supprimée ou annulée ────────────────────
app.post('/api/webhook-qb', async (req, res) => {
  console.log('Webhook QB: requête reçue, content-length =', req.headers['content-length']);
  const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from(JSON.stringify(req.body));
  const webhookToken = process.env.QB_WEBHOOK_TOKEN;
  const signature = req.headers['intuit-signature'];
  if (!webhookToken) {
    console.warn('Webhook QB: QB_WEBHOOK_TOKEN non configuré — la vérification de signature est DÉSACTIVÉE. À corriger côté variables d\'environnement.');
  }
  if (webhookToken && signature) {
    const hash = crypto_wb.createHmac('sha256', webhookToken).update(rawBody).digest('base64');
    if (hash !== signature) { console.log('Webhook QB: signature invalide — vérifie que QB_WEBHOOK_TOKEN correspond exactement au "Webhooks Verifier Token" du Intuit Developer Dashboard.'); return res.status(401).json({ error: 'Invalid signature' }); }
  } else if (webhookToken && !signature) {
    console.warn('Webhook QB: aucun header intuit-signature reçu — requête ignorée ou test manuel ?');
  }
  res.status(200).json({ success: true });
  try {
    const payload = JSON.parse(rawBody.toString());
    const notifCount = (payload.eventNotifications || []).length;
    console.log('Webhook QB: payload reçu,', notifCount, 'notification(s)');
    for (const notif of (payload.eventNotifications || [])) {
      const realmId = notif.realmId;
      const entities = notif.dataChangeEvent?.entities || [];
      console.log('Webhook QB: realmId =', realmId, '-', entities.length, 'entité(s):', entities.map(e => e.name + '/' + e.operation).join(', '));
      for (const entity of entities) {
        if (entity.name !== 'Invoice') continue;
        const invoiceId = entity.id;
        const operation = entity.operation;

        // ─── Suppression / annulation: on RESTAURE l'inventaire ───────────
        // On ne peut plus interroger l'API pour une facture supprimée, donc
        // on se base sur ce qu'on a nous-même déduit et enregistré au moment
        // de la création (voir plus bas: webhookProcessedInvoices.lines).
        if (operation === 'Delete' || operation === 'Void') {
          console.log('Webhook QB: facture', operation, invoiceId, '- tentative de restauration de l\'inventaire.');
          try {
            if (!db) { console.warn('Webhook QB: DB non connectée, restauration impossible.'); continue; }
            // On "réclame" la restauration atomiquement pour éviter de la faire 2 fois
            // si Delete/Void se déclenche plusieurs fois pour la même facture.
            // Note: driver mongodb v6 retourne le document directement (ou null),
            // pas enveloppé dans { value } comme les anciennes versions.
            const record = await db.collection('webhookProcessedInvoices').findOneAndUpdate(
              { realmId, invoiceId, reversed: { $ne: true } },
              { $set: { reversed: true, reversedAt: new Date(), reversedReason: operation } },
              { returnDocument: 'before' }
            );
            if (!record) {
              console.log('Webhook QB: aucune déduction connue (ou déjà restaurée) pour la facture', invoiceId, '- rien à faire.');
              continue;
            }
            for (const line of (record.lines || [])) {
              await db.collection('inventory').updateOne({ name: line.productName }, { $inc: { stock: line.qty } }, { upsert: true });
              await db.collection('productionLog').insertOne({
                name: line.productName,
                qty: line.qty,
                note: 'Facture QB #' + (record.docNumber || invoiceId) + ' ' + (operation === 'Delete' ? 'supprimée' : 'annulée') + ' (webhook)',
                type: 'production',
                createdAt: new Date(),
                createdBy: 'quickbooks-webhook'
              });
              console.log('Webhook QB: inventaire restauré:', line.productName, '+' + line.qty);
            }
          } catch(e) { console.error('Webhook QB erreur restauration facture:', invoiceId, e.message, e.stack); }
          continue;
        }

        if (!['Create', 'Update'].includes(operation)) continue;
        console.log('Webhook QB: facture', operation, invoiceId);
        try {
          const token = await getAnyValidToken(realmId);
          const effectiveRealmId = realmId || token.realmId;
          const invData = await (await fetch(`https://quickbooks.api.intuit.com/v3/company/${effectiveRealmId}/invoice/${invoiceId}?minorversion=65`, { headers: { 'Authorization': 'Bearer ' + token.token, 'Accept': 'application/json' } })).json();
          const invoice = invData.Invoice;
          if (!invoice) { console.log('Webhook QB: facture introuvable via API pour id =', invoiceId, '- réponse:', JSON.stringify(invData).slice(0, 300)); continue; }

          // ─── Anti-double-déduction ────────────────────────────────────────
          // QuickBooks envoie souvent un événement "Create" ET un événement
          // "Update" quasi simultanés pour une même facture tout juste créée
          // (recalcul interne, synchronisation de champs, etc.). Sans garde-fou,
          // chacun de ces événements déclenchait une déduction d'inventaire,
          // donc la même facture était déduite 2 fois (parfois plus).
          // On "réserve" la facture en l'insérant AVANT de déduire (via l'index
          // unique realmId+invoiceId) — si deux événements arrivent presque
          // en même temps, un seul gagne la course et déduit réellement.
          let reserved = true;
          if (db) {
            try {
              await db.collection('webhookProcessedInvoices').insertOne({ realmId: effectiveRealmId, invoiceId, processedAt: new Date(), docNumber: invoice.DocNumber || null, lines: [], reversed: false });
            } catch(dupErr) {
              if (dupErr.code === 11000) {
                reserved = false;
                console.log('Webhook QB: facture', invoiceId, 'déjà traitée (ou en cours de traitement) - déduction ignorée (anti-doublon).');
              } else { throw dupErr; }
            }
          }
          if (!reserved) continue;

          if (qbProducts.length === 0) { await loadQbProducts(effectiveRealmId, token.token); }
          const deductedLines = [];
          for (const line of (invoice.Line || [])) {
            if (line.DetailType !== 'SalesItemLineDetail') continue;
            const detail = line.SalesItemLineDetail;
            const qty = detail?.Qty || 0;
            const itemId = detail?.ItemRef?.value;
            if (!qty || !itemId) continue;
            let qbItem = qbProducts.find(p => p.Id === itemId);
            if (!qbItem) {
              // Item pas dans le cache (nouveau produit ?) — on recharge une fois.
              await loadQbProducts(effectiveRealmId, token.token);
              qbItem = qbProducts.find(p => p.Id === itemId);
            }
            const qbItemName = qbItem?.Name || '';
            const productName = matchInventoryProduct(qbItemName);
            if (!qbItemName) { console.log('Webhook QB: item QB introuvable pour Id =', itemId, '- inventaire non déduit pour cette ligne.'); continue; }
            if (!productName) { console.log('Webhook QB: item "' + qbItemName + '" n\'est pas dans INVENTORY_PRODUCTS - ignoré (normal si ce n\'est pas un produit d\'inventaire suivi).'); continue; }
            if (db) {
              await db.collection('inventory').updateOne({ name: productName }, { $inc: { stock: -qty } }, { upsert: true });
              await db.collection('productionLog').insertOne({ name: productName, qty: -qty, note: 'Facture QB #' + (invoice.DocNumber || invoiceId) + ' (webhook)', type: 'deduction', createdAt: new Date(), createdBy: 'quickbooks-webhook' });
              console.log('Webhook QB: inventaire déduit avec succès:', productName, '-' + qty);
              deductedLines.push({ productName, qty });
            } else {
              console.warn('Webhook QB: DB non connectée, déduction impossible pour', productName);
            }
          }
          // On enregistre ce qui a été déduit pour pouvoir le restaurer plus
          // tard si la facture est supprimée ou annulée.
          if (db && deductedLines.length) {
            await db.collection('webhookProcessedInvoices').updateOne({ realmId: effectiveRealmId, invoiceId }, { $set: { lines: deductedLines } });
          }
        } catch(e) { console.error('Webhook QB erreur facture:', invoiceId, e.message, e.stack); }
      }
    }
  } catch(e) { console.error('Webhook QB parsing erreur:', e.message, e.stack); }
});

app.get('*', (req, res) => {
  if (req.path.startsWith('/api/') || req.path === '/callback') { res.status(404).json({ error: 'Not found' }); }
  else { res.sendFile(path.join(__dirname, 'index.html')); }
});

const PORT = process.env.PORT || 3000;
connectMongo().then(() => {
  app.listen(PORT, () => console.log(`Phil & Fred Invoice App running on port ${PORT}`));
});
