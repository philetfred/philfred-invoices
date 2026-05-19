const express = require('express');
const fetch = require('node-fetch');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Config — ces valeurs viennent des variables d'environnement Render
const CLIENT_ID = process.env.QB_CLIENT_ID;
const CLIENT_SECRET = process.env.QB_CLIENT_SECRET;
const REDIRECT_URI = process.env.QB_REDIRECT_URI || 'https://philfred-invoices.onrender.com/callback';

// Store tokens en mémoire (simple pour usage solo)
let tokenStore = {
  accessToken: null,
  refreshToken: null,
  realmId: null,
  expiresAt: null
};

// ─── OAuth Flow ───────────────────────────────────────────────────────────────

// Step 1: Redirect to QuickBooks login
app.get('/auth', (req, res) => {
  const scope = 'com.intuit.quickbooks.accounting';
  const state = Math.random().toString(36).substring(7);
  const authUrl = `https://appcenter.intuit.com/connect/oauth2?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=${scope}&state=${state}&prompt=select_account`;
  res.redirect(authUrl);
});

// Step 2: QuickBooks redirects back here with code
app.get('/callback', async (req, res) => {
  const { code, realmId } = req.query;
  if (!code) return res.status(400).send('No code received');

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
      tokenStore = {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        realmId: realmId,
        expiresAt: Date.now() + (data.expires_in * 1000)
      };
      res.redirect('/?connected=true');
    } else {
      res.redirect('/?error=auth_failed');
    }
  } catch (err) {
    res.redirect('/?error=' + err.message);
  }
});

// ─── Token Management ─────────────────────────────────────────────────────────

async function getValidToken() {
  if (!tokenStore.accessToken) throw new Error('Not authenticated');
  
  // Refresh if expired or expiring in 5 min
  if (Date.now() > tokenStore.expiresAt - 300000) {
    const credentials = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    const response = await fetch('https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer', {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + credentials,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: `grant_type=refresh_token&refresh_token=${tokenStore.refreshToken}`
    });
    const data = await response.json();
    if (data.access_token) {
      tokenStore.accessToken = data.access_token;
      tokenStore.refreshToken = data.refresh_token;
      tokenStore.expiresAt = Date.now() + (data.expires_in * 1000);
    } else {
      tokenStore.accessToken = null;
      throw new Error('Token refresh failed - please reconnect');
    }
  }
  return tokenStore.accessToken;
}

// Get customer details including price rules
app.get('/api/customer/:id', async (req, res) => {
  try {
    const token = await getValidToken();
    const url = `https://quickbooks.api.intuit.com/v3/company/${tokenStore.realmId}/customer/${req.params.id}?minorversion=65`;
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

let priceRules = [
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

app.get('/api/price-rules', (req, res) => {
  res.json(priceRules);
});

app.post('/api/price-rules', (req, res) => {
  priceRules = req.body;
  res.json({ success: true });
});

app.post('/api/price-rules/add', (req, res) => {
  const rule = req.body;
  // Remove existing rule for same client
  priceRules = priceRules.filter(r => r.name.toLowerCase() !== rule.name.toLowerCase());
  priceRules.push(rule);
  res.json({ success: true });
});

app.delete('/api/price-rules/:index', (req, res) => {
  const index = parseInt(req.params.index);
  priceRules.splice(index, 1);
  res.json({ success: true });
});

// ─── Tax Codes ────────────────────────────────────────────────────────────────

app.get('/api/taxcodes', async (req, res) => {
  try {
    const token = await getValidToken();
    const url = `https://quickbooks.api.intuit.com/v3/company/${tokenStore.realmId}/query?query=SELECT * FROM TaxCode&minorversion=65`;
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
    const token = await getValidToken();
    const headers = {
      'Authorization': 'Bearer ' + token,
      'Accept': 'application/json'
    };
    const base = `https://quickbooks.api.intuit.com/v3/company/${tokenStore.realmId}`;
    
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

app.get('/api/status', (req, res) => {
  res.json({
    connected: !!tokenStore.accessToken,
    realmId: tokenStore.realmId
  });
});

// ─── QuickBooks API Proxy ─────────────────────────────────────────────────────

app.post('/api/qb', async (req, res) => {
  const { query } = req.body;
  try {
    const token = await getValidToken();
    const url = `https://quickbooks.api.intuit.com/v3/company/${tokenStore.realmId}/query?query=${encodeURIComponent(query)}&minorversion=65`;
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
    const token = await getValidToken();
    const url = `https://quickbooks.api.intuit.com/v3/company/${tokenStore.realmId}/${endpoint}?minorversion=65`;
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

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/import', (req, res) => {
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
app.listen(PORT, () => console.log(`Phil & Fred Invoice App running on port ${PORT}`));
