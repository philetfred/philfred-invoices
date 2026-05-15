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

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Phil & Fred Invoice App running on port ${PORT}`));
