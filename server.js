const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Proxy pour QuickBooks API - évite les problèmes CORS
app.post('/api/qb', async (req, res) => {
  const { endpoint, method, accessToken, realmId, body } = req.body;
  try {
    const url = `https://quickbooks.api.intuit.com/v3/company/${realmId}/${endpoint}?minorversion=65`;
    const options = {
      method: method || 'GET',
      headers: {
        'Authorization': 'Bearer ' + accessToken,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      }
    };
    if (body) options.body = JSON.stringify(body);
    const response = await fetch(url, options);
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Refresh token
app.post('/api/refresh', async (req, res) => {
  const { refreshToken, clientId, clientSecret } = req.body;
  try {
    const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    const response = await fetch('https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer', {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + credentials,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: `grant_type=refresh_token&refresh_token=${refreshToken}`
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Phil & Fred Invoice App running on port ${PORT}`));
