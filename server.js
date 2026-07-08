const express = require('express');
const fetch = require('node-fetch');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.json());

// ─── Simple cookie parser (no dependency needed) ───────────────────────────────
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

// ─── MongoDB Connection ───────────────────────────────────────────────────────
const MONGODB_URI = process.env.MONGODB_URI;
let db = null;

// Default users (stored in MongoDB, initialized on first run)
const defaultAppUsers = [
  { username: 'Fred',  passwordHash: '7d301c9cefaf53d6f7b43a7cb228e18f8466c62f62fe87aaf621132eba509bb0', role: 'admin' },
  { username: 'AlexB', passwordHash: 'f5286a7722c969aee390525c7309e98864bd9057b6983c600469b80d31ad4997', role: 'employe' },
  { username: 'Alex',  passwordHash: '9b5e34a4f2d715c4ea89842da98bbeae766851584b1e746457f3b1b887d3d9be', role: 'employe' },
  { username: 'MathA', passwordHash: 'fcf5077d5abff23bae284cdda0f2533a5d5860a9d2442943f78b603755e92bc5', role: 'employe' },
];

async function connectMongo() {
  if (!MONGODB_URI) {
    console.log('No MONGODB_URI set, using in-memory price rules');
    return;
  }
  try {
    const client = new MongoClient(MONGODB_URI, {
      tls: true,
      tlsAllowInvalidCertificates: true,
      serverSelectionTimeoutMS: 10000
    });
    await client.connect();
    db = client.db('philfred');
    console.log('Connected to MongoDB');
    // Initialize price rules in DB if empty
    const count = await db.collection('priceRules').countDocuments();
    if (count === 0) {
      await db.collection('priceRules').insertMany(defaultPriceRules);
      console.log('Price rules initialized in MongoDB');
    }
    // Initialize app users if empty
    const userCount = await db.collection('appUsers').countDocuments();
    if (userCount === 0) {
      await db.collection('appUsers').insertMany(defaultAppUsers);
      console.log('App users initialized in MongoDB');
    }
    // Create index on appSessions for faster lookup
    await db.collection('appSessions').createIndex({ sessionId: 1 });
    await db.collection('appUsers').createIndex({ username: 1 });
  } catch(err) {
    console.error('MongoDB connection error:', err);
  }
}

// ─── Session Management (multi-utilisateur) ────────────────────────────────────
// Chaque navigateur a un cookie 'sessionId' unique. Les tokens QuickBooks
// sont stockés dans MongoDB, indexés par sessionId, pour permettre à
// plusieurs personnes de se connecter avec leur propre compte QB en même temps.

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
    await db.collection('sessions').updateOne(
      { sessionId },
      { $set: { ...tokenData, sessionId, updatedAt: new Date() } },
      { upsert: true }
    );
  } else {
    memorySessions[sessionId] = tokenData;
  }
}

async function getSessionToken(sessionId) {
  if (db) {
    return await db.collection('sessions').findOne({ sessionId });
  }
  return memorySessions[sessionId] || null;
}

// Fallback en mémoire si MongoDB n'est pas connecté
const memorySessions = {};

// Config — ces valeurs viennent des variables d'environnement Render
const CLIENT_ID = process.env.QB_CLIENT_ID;
const CLIENT_SECRET = process.env.QB_CLIENT_SECRET;
const REDIRECT_URI = process.env.QB_REDIRECT_URI || 'https://philfred-invoices.onrender.com/callback';

// ─── OAuth Flow ───────────────────────────────────────────────────────────────

// Step 1: Redirect to QuickBooks login
app.get('/auth', (req, res) => {
  const sessionId = getOrCreateSessionId(req, res);
  const scope = 'com.intuit.quickbooks.accounting';
  // On encode le sessionId dans le state pour le retrouver au callback
  const state = sessionId + '.' + Math.random().toString(36).substring(7);
  const authUrl = `https://appcenter.intuit.com/connect/oauth2?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=${scope}&state=${state}&prompt=select_account`;
  res.redirect(authUrl);
});

// Step 2: QuickBooks redirects back here with code
app.get('/callback', async (req, res) => {
  const { code, realmId, state } = req.query;
  if (!code) return res.status(400).send('No code received');

  // Récupère le sessionId à partir du state, ou du cookie en fallback
  let sessionId = state ? state.split('.')[0] : null;
  if (!sessionId || sessionId.length !== 48) {
    sessionId = getOrCreateSessionId(req, res);
  } else {
    res.setHeader('Set-Cookie', `sessionId=${sessionId}; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax`);
  }

  try {
    const credentials = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    const response = await fetch('https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer', {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + credentials,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: `grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`
    });

    const data = await response.json();
    if (data.access_token) {
      await saveSessionToken(sessionId, {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        realmId: realmId,
        expiresAt: Date.now() + (data.expires_in * 1000)
      });
      res.redirect('/?connected=true');
    } else {
      res.redirect('/?error=auth_failed');
    }
  } catch (err) {
    res.redirect('/?error=' + err.message);
  }
});

// ─── Token Management ─────────────────────────────────────────────────────────

async function getValidToken(req, res) {
  const sessionId = getOrCreateSessionId(req, res);
  const session = await getSessionToken(sessionId);

  if (!session || !session.accessToken) throw new Error('Not authenticated');

  // Refresh if expired or expiring in 5 min
  if (Date.now() > session.expiresAt - 300000) {
    const credentials = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    const response = await fetch('https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer', {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + credentials,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: `grant_type=refresh_token&refresh_token=${session.refreshToken}`
    });
    const data = await response.json();
    if (data.access_token) {
      session.accessToken = data.access_token;
      session.refreshToken = data.refresh_token;
      session.expiresAt = Date.now() + (data.expires_in * 1000);
      await saveSessionToken(sessionId, session);
    } else {
      await saveSessionToken(sessionId, { accessToken: null, refreshToken: null, realmId: null, expiresAt: null });
      throw new Error('Token refresh failed - please reconnect');
    }
  }
  return { token: session.accessToken, realmId: session.realmId };
}

// Get customer details including price rules
app.get('/api/customer/:id', async (req, res) => {
  try {
    const { token, realmId } = await getValidToken(req, res);
    const url = `https://quickbooks.api.intuit.com/v3/company/${realmId}/customer/${req.params.id}?minorversion=65`;
    const response = await fetch(url, {
      headers: {
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/json'
      }
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

// ─── Price Rules Storage ──────────────────────────────────────────────────────

const defaultPriceRules = [
  // 20% de marge
  { name: 'IGA extra Super Marché Famille Primeau inc. Beauharnois', type: 'percent', value: -20 },
  { name: 'IGA extra Super Marché Primeau et fils inc.', type: 'percent', value: -20 },
  // 22% de marge
  { name: 'IGA extra Gladu (2747-6761 Québec Inc.)', type: 'percent', value: -22 },
  { name: 'IGA Extra Laprairie', type: 'percent', value: -22 },
  { name: 'IGA extra Les Marchés Lambert Chambly', type: 'percent', value: -22 },
  { name: 'IGA extra Les Marchés Lambert Richelieu', type: 'percent', value: -22 },
  { name: 'IGA extra Yan Gladu Douglas (9425-6211 Qc Inc.)', type: 'percent', value: -22 },
  { name: 'IGA Gladu Saint-Luc (9425-6260 Qc Inc.)', type: 'percent', value: -22 },
  { name: 'IGA Groupe Pro 40 inc.', type: 'percent', value: -22 },
  { name: 'IGA Supermarché Laplante inc.', type: 'percent', value: -22 },
  { name: 'IGA Candiac Sobeys Capital Inc', type: 'percent', value: -22 },
  // 25% de marge
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
  // 30% de marge
  { name: 'IGA extra Marché Vincent inc.', type: 'percent', value: -30 },
  { name: 'Pasquier Delson', type: 'percent', value: -30 },
  { name: 'Pasquier St-Jean-sur-Richelieu', type: 'percent', value: -30 },
  // Super C -8$ fixe
  { name: 'super_c_pattern', type: 'pattern_fixed', value: -8, pattern: 'super c' }
];

let priceRules = [...defaultPriceRules];

app.get('/api/price-rules', async (req, res) => {
  try {
    if (db) {
      const rules = await db.collection('priceRules').find({}, { projection: { _id: 0 } }).toArray();
      return res.json(rules);
    }
    res.json(priceRules);
  } catch(err) {
    res.json(priceRules);
  }
});

app.post('/api/price-rules', async (req, res) => {
  try {
    if (db) {
      await db.collection('priceRules').deleteMany({});
      if (req.body.length > 0) await db.collection('priceRules').insertMany(req.body);
    } else {
      priceRules = req.body;
    }
    res.json({ success: true });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/price-rules/add', async (req, res) => {
  const rule = req.body;
  try {
    if (db) {
      await db.collection('priceRules').deleteOne({ name: new RegExp('^' + rule.name + '$', 'i') });
      await db.collection('priceRules').insertOne(rule);
    } else {
      priceRules = priceRules.filter(r => r.name.toLowerCase() !== rule.name.toLowerCase());
      priceRules.push(rule);
    }
    res.json({ success: true });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/price-rules/:index', async (req, res) => {
  const index = parseInt(req.params.index);
  try {
    if (db) {
      const rules = await db.collection('priceRules').find({}, { projection: { _id: 0 } }).toArray();
      if (rules[index]) {
        await db.collection('priceRules').deleteOne({ name: rules[index].name });
      }
    } else {
      priceRules.splice(index, 1);
    }
    res.json({ success: true });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Tax Codes ────────────────────────────────────────────────────────────────

app.get('/api/taxcodes', async (req, res) => {
  try {
    const { token, realmId } = await getValidToken(req, res);
    const url = `https://quickbooks.api.intuit.com/v3/company/${realmId}/query?query=SELECT * FROM TaxCode&minorversion=65`;
    const response = await fetch(url, {
      headers: {
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/json'
      }
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

// Get next invoice number (checks Invoice AND CreditMemo)
app.get('/api/next-invoice-number', async (req, res) => {
  try {
    const { token, realmId } = await getValidToken(req, res);
    const headers = {
      'Authorization': 'Bearer ' + token,
      'Accept': 'application/json'
    };
    const base = `https://quickbooks.api.intuit.com/v3/company/${realmId}`;
    
    // Fetch invoices and credit memos in parallel
    const [invRes, cmRes] = await Promise.all([
      fetch(`${base}/query?query=SELECT DocNumber FROM Invoice MAXRESULTS 100&minorversion=65`, { headers }),
      fetch(`${base}/query?query=SELECT DocNumber FROM CreditMemo MAXRESULTS 100&minorversion=65`, { headers })
    ]);
    
    const invData = await invRes.json();
    const cmData = await cmRes.json();
    
    const allDocs = [
      ...(invData.QueryResponse?.Invoice || []),
      ...(cmData.QueryResponse?.CreditMemo || [])
    ];
    
    let maxNum = 0;
    allDocs.forEach(doc => {
      if (doc.DocNumber) {
        const num = parseInt(doc.DocNumber.replace(/[^0-9]/g, ''));
        if (!isNaN(num) && num > maxNum) maxNum = num;
      }
    });
    
    res.json({ nextNumber: String(maxNum + 1) });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

// ─── Status ───────────────────────────────────────────────────────────────────

app.get('/api/status', async (req, res) => {
  const sessionId = getOrCreateSessionId(req, res);
  const session = await getSessionToken(sessionId);
  res.json({
    connected: !!(session && session.accessToken),
    realmId: session ? session.realmId : null
  });
});

// ─── QuickBooks API Proxy ─────────────────────────────────────────────────────

app.post('/api/qb', async (req, res) => {
  const { query } = req.body;
  try {
    const { token, realmId } = await getValidToken(req, res);
    const url = `https://quickbooks.api.intuit.com/v3/company/${realmId}/query?query=${encodeURIComponent(query)}&minorversion=65`;
    const response = await fetch(url, {
      headers: {
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/json'
      }
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

app.post('/api/qb-post', async (req, res) => {
  const { endpoint, body } = req.body;
  try {
    const { token, realmId } = await getValidToken(req, res);
    const url = `https://quickbooks.api.intuit.com/v3/company/${realmId}/${endpoint}?minorversion=65`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});


// ─── Parse PDF via Claude API ─────────────────────────────────────────────────

app.post('/api/parse-pdf', async (req, res) => {
  const { pdfBase64 } = req.body;
  if (!pdfBase64) return res.status(400).json({ error: 'Missing pdfBase64' });

  const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'ANTHROPIC_API_KEY not set on server' });

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        messages: [{
          role: 'user',
          content: [
            {
              type: 'document',
              source: { type: 'base64', media_type: 'application/pdf', data: pdfBase64 }
            },
            {
              type: 'text',
              text: `Extract the purchase order data from this PDF. Return ONLY a valid JSON object (no markdown, no backticks) with this exact structure:
{
  "po_number": "the purchase order number (BON DE COMMANDE #)",
  "supplier_name": "the store/magasin name (e.g. Pasquier St-Jean-sur-Richelieu)",
  "delivery_date": "YYYY-MM-DD format of the planned delivery date",
  "items": [
    {
      "description": "full product description from the PDF",
      "cases": 4
    }
  ]
}
Return only the JSON, nothing else.`
            }
          ]
        }]
      })
    });

    const data = await response.json();
    if (data.error) return res.status(500).json({ error: data.error.message });
    const text = data.content?.[0]?.text || '';
    // Try to parse JSON from response
    let parsed;
    try {
      parsed = JSON.parse(text.trim());
    } catch(e) {
      const match = text.match(/\{[\s\S]*\}/);
      if (match) parsed = JSON.parse(match[0]);
      else return res.status(500).json({ error: 'Could not parse Claude response', raw: text });
    }
    res.json(parsed);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── App Authentication ───────────────────────────────────────────────────────

const crypto_builtin = require('crypto');

function hashPassword(password) {
  return crypto_builtin.createHash('sha256').update(password).digest('hex');
}

// Middleware — vérifie le cookie de session app (différent du token QB)
async function requireAppAuth(req, res, next) {
  const appSessionId = req.cookies.appSessionId;
  if (!appSessionId) return res.redirect('/login');
  if (db) {
    const session = await db.collection('appSessions').findOne({ sessionId: appSessionId });
    if (!session) return res.redirect('/login');
    req.appUser = session;
  }
  next();
}

async function requireAdmin(req, res, next) {
  const appSessionId = req.cookies.appSessionId;
  if (!appSessionId) return res.status(401).json({ error: 'Non authentifié' });
  if (db) {
    const session = await db.collection('appSessions').findOne({ sessionId: appSessionId });
    if (!session || session.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
    req.appUser = session;
  }
  next();
}

// Login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Login POST
app.post('/api/app-login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ success: false, error: 'Champs manquants' });

  try {
    const hash = hashPassword(password);
    let user = null;
    if (db) {
      user = await db.collection('appUsers').findOne({ username, passwordHash: hash });
    } else {
      user = defaultAppUsers.find(u => u.username === username && u.passwordHash === hash);
    }
    if (!user) return res.json({ success: false, error: 'Nom d\'utilisateur ou mot de passe incorrect' });

    // Create app session
    const sessionId = crypto_builtin.randomBytes(24).toString('hex');
    if (db) {
      await db.collection('appSessions').insertOne({
        sessionId,
        username: user.username,
        role: user.role,
        createdAt: new Date()
      });
    }
    res.setHeader('Set-Cookie', `appSessionId=${sessionId}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`);
    res.json({ success: true, role: user.role });
  } catch(e) {
    res.json({ success: false, error: e.message });
  }
});

// Logout
app.post('/api/app-logout', async (req, res) => {
  const appSessionId = req.cookies.appSessionId;
  if (appSessionId && db) {
    await db.collection('appSessions').deleteOne({ sessionId: appSessionId });
  }
  res.setHeader('Set-Cookie', 'appSessionId=; HttpOnly; Path=/; Max-Age=0');
  res.json({ success: true });
});

// App session status
app.get('/api/app-status', async (req, res) => {
  const appSessionId = req.cookies.appSessionId;
  if (!appSessionId) return res.json({ loggedIn: false });
  if (db) {
    const session = await db.collection('appSessions').findOne({ sessionId: appSessionId });
    if (!session) return res.json({ loggedIn: false });
    return res.json({ loggedIn: true, username: session.username, role: session.role });
  }
  res.json({ loggedIn: false });
});

// User management (admin only)
app.get('/api/app-users', requireAdmin, async (req, res) => {
  if (!db) return res.json([]);
  const users = await db.collection('appUsers').find({}, { projection: { passwordHash: 0 } }).toArray();
  res.json(users);
});

app.post('/api/app-users/add', requireAdmin, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) return res.status(400).json({ error: 'Champs manquants' });
  const passwordHash = hashPassword(password);
  if (db) {
    await db.collection('appUsers').deleteOne({ username });
    await db.collection('appUsers').insertOne({ username, passwordHash, role });
  }
  res.json({ success: true });
});

app.delete('/api/app-users/:username', requireAdmin, async (req, res) => {
  if (db) await db.collection('appUsers').deleteOne({ username: req.params.username });
  res.json({ success: true });
});

app.get('/', requireAppAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin', requireAppAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/import', requireAppAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'import.html'));
});

app.get('/auth', (req, res) => {
  // handled above
});

app.get('*', (req, res) => {
  // Only serve index.html for non-API routes
  if (req.path.startsWith('/api/') || req.path === '/callback') {
    res.status(404).json({ error: 'Not found' });
  } else {
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

const PORT = process.env.PORT || 3000;
connectMongo().then(() => {
  app.listen(PORT, () => console.log(`Phil & Fred Invoice App running on port ${PORT}`));
});
