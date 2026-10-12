const express = require("express");
const path = require("path");
const crypto = require("crypto");
const Parser = require("rss-parser");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== MIDDLEWARE ====================

app.disable("x-powered-by");
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false }));

app.use(
  express.static(path.join(__dirname, "public"))
);

// ==================== DEMO ACCOUNT STORE ====================
// DEMO ONLY: MongoDB dependency has been removed from this app.
// Accounts live in a local JSON file (data/demo-users.json) so `npm start`
// keeps working offline. Passwords are NEVER stored in plaintext — only
// bcrypt hashes. The Atlas database is untouched; old Atlas accounts do NOT
// carry over to this demo store. Nothing here is a permanent account.

const fs = require("fs");

const DEMO_DATA_DIR = path.join(__dirname, "data");
const DEMO_USERS_FILE = path.join(DEMO_DATA_DIR, "demo-users.json");

function readDemoUsers() {
  try {
    const raw = fs.readFileSync(DEMO_USERS_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeDemoUsers(users) {
  fs.mkdirSync(DEMO_DATA_DIR, { recursive: true });
    fs.writeFileSync(DEMO_USERS_FILE, JSON.stringify(users, null, 2), "utf8");
}

function findDemoUserByEmail(email) {
  return readDemoUsers().find((u) => u.email === email) || null;
}

function findDemoUserById(id) {
  return readDemoUsers().find((u) => u.id === id) || null;
}

// ==================== DEMO SESSION (SIGNED TOKEN) ====================
// Stateless HMAC-signed token in an HttpOnly cookie. No server-side store,
// so it works on Vercel serverless. Short-lived (24h). DEMO ONLY — not real
// authentication. SESSION_SECRET signs the token; it is never logged.

const DEMO_SESSION_COOKIE = "mahaupdate.demo";
const DEMO_SESSION_TTL_MS = 24 * 60 * 60 * 1000;

function getDemoSecret() {
  return process.env.SESSION_SECRET || null;
}

function base64UrlEncode(input) {
  return Buffer.from(input, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlDecode(input) {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - (padded.length % 4)) % 4;
  return Buffer.from(padded + "=".repeat(padLength), "base64").toString(
    "utf8"
  );
}

function signDemoToken(payloadBase64, secret) {
  return crypto
    .createHmac("sha256", secret)
    .update(payloadBase64)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function createDemoToken(user, secret) {
  const payload = base64UrlEncode(
    JSON.stringify({
      sub: user.id,
      email: user.email,
      name: user.name,
      exp: Date.now() + DEMO_SESSION_TTL_MS
    })
  );
  const signature = signDemoToken(payload, secret);
  return payload + "." + signature;
}

function verifyDemoToken(token, secret) {
  if (typeof token !== "string" || !token.includes(".")) return null;
  const [payloadBase64, signature] = token.split(".");
  if (!payloadBase64 || !signature) return null;

  const expected = signDemoToken(payloadBase64, secret);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  let payload;
  try {
    payload = JSON.parse(base64UrlDecode(payloadBase64));
  } catch {
    return null;
  }

  if (!payload.sub || !payload.email || !payload.exp) return null;
  if (Date.now() > Number(payload.exp)) return null;
  return payload;
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index === -1) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key) out[key] = decodeURIComponent(value);
  }
  return out;
}

function setDemoCookie(res, token) {
  const parts = [
    DEMO_SESSION_COOKIE + "=" + encodeURIComponent(token),
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=" + Math.floor(DEMO_SESSION_TTL_MS / 1000)
  ];
  if (process.env.NODE_ENV === "production") parts.push("Secure");
  res.append("Set-Cookie", parts.join("; "));
}

function clearDemoCookie(res) {
  const parts = [
    DEMO_SESSION_COOKIE + "=;",
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=0"
  ];
  if (process.env.NODE_ENV === "production") parts.push("Secure");
  res.append("Set-Cookie", parts.join("; "));
}

function getDemoSession(req) {
  const secret = getDemoSecret();
  if (!secret) return null;
  const cookies = parseCookies(req);
  const token = cookies[DEMO_SESSION_COOKIE];
  if (!token) return null;
  return verifyDemoToken(token, secret);
}

// ==================== SESSION CONFIGURATION ====================
// DEMO mode: SESSION_SECRET signs demo tokens (required). There is no
// database, no session store, and no process.exit() at import time — public
// routes (/api/health, /api/news, frontend) always work on Vercel.

const hasSessionSecret = Boolean(process.env.SESSION_SECRET);

if (!hasSessionSecret) {
  console.error(
    "SESSION_SECRET is missing. Set it in .env (local) and in Vercel Project -> Settings -> Environment Variables (Production)."
  );
}

app.set("trust proxy", 1);

// Require SESSION_SECRET only for demo auth routes, not for public routes.

// ==================== AUTH HELPERS ====================

function getSafeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email
  };
}

function requireDemoSecret(req, res, next) {
  if (!getDemoSecret()) {
    return res.status(500).json({
      success: false,
      message: "Demo session is not configured (SESSION_SECRET missing)."
    });
  }
  return next();
}

function requireLogin(req, res, next) {
  const secret = getDemoSecret();
  if (!secret) {
    return res.status(500).json({
      success: false,
      message: "Demo session is not configured (SESSION_SECRET missing)."
    });
  }

  const payload = getDemoSession(req);
  if (!payload) {
    return res.status(401).json({
      success: false,
      message: "Please log in first (demo session expired or invalid)."
    });
  }

  req.demoUser = payload;
  return next();
}

// ==================== AUTH API (DEMO ONLY) ====================
// DEMO login/register: same routes, same validation, bcrypt hashing.
// Register stores a bcrypt hash in data/demo-users.json (local/temporary).
// NO plaintext passwords anywhere. Old Atlas accounts are untouched and do
// NOT work here — a fresh demo registration is required.

// Register
app.post("/api/auth/register", requireDemoSecret, async (req, res) => {
  try {
    const name =
      typeof req.body.name === "string"
        ? req.body.name.trim()
        : "";

    const email =
      typeof req.body.email === "string"
        ? req.body.email.trim().toLowerCase()
        : "";

    const password =
      typeof req.body.password === "string"
        ? req.body.password
        : "";

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email and password are required."
      });
    }

    if (name.length < 2 || name.length > 80) {
      return res.status(400).json({
        success: false,
        message: "Name must be between 2 and 80 characters."
      });
    }

    if (
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email address."
      });
    }

    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({
        success: false,
        message: "Password must be 8 to 72 characters long."
      });
    }

    if (findDemoUserByEmail(email)) {
      return res.status(409).json({
        success: false,
        message: "A demo account with this email already exists."
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = {
      id: crypto.randomUUID(),
      name,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    // IMPORTANT: Vercel's serverless filesystem is READ-ONLY, so this write
    // fails there. Attempt the write FIRST and only claim success (201) when
    // it genuinely persisted. This keeps local `npm start` fully working
    // while production fails honestly with 503 instead of a false account.
    const users = readDemoUsers();
    users.push(user);
    try {
      writeDemoUsers(users);
    } catch (error) {
      // Report honestly instead of faking success.
      console.error("Demo store write failed:", error.message);
      return res.status(503).json({
        success: false,
        demo: true,
        message:
          "Demo registration is unavailable on this deployment (read-only storage). No account was created. Please try local development."
      });
    }

    setDemoCookie(res, createDemoToken(user, getDemoSecret()));

    return res.status(201).json({
      success: true,
      demo: true,
      message:
        "Demo registration successful. This is a demo account only, not a permanent account.",
      user: getSafeUser(user)
    });
  } catch (error) {
    console.error("Demo registration error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Demo registration failed. Please try again."
    });
  }
});

// Login
app.post("/api/auth/login", requireDemoSecret, async (req, res) => {
  try {
    const email =
      typeof req.body.email === "string"
        ? req.body.email.trim().toLowerCase()
        : "";

    const password =
      typeof req.body.password === "string"
        ? req.body.password
        : "";

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required."
      });
    }

    const user = findDemoUserByEmail(email);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password (demo accounts only)."
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordMatches) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password (demo accounts only)."
      });
    }

    setDemoCookie(res, createDemoToken(user, getDemoSecret()));

    return res.json({
      success: true,
      demo: true,
      message: "Demo login successful.",
      user: getSafeUser(user)
    });
  } catch (error) {
    console.error("Demo login error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Demo login failed. Please try again."
    });
  }
});

// Get current logged-in demo user
app.get("/api/auth/me", requireLogin, async (req, res) => {
  try {
    const user = findDemoUserById(req.demoUser.sub);

    if (!user) {
      clearDemoCookie(res);
      return res.status(401).json({
        success: false,
        message: "Demo account not found. Please log in again."
      });
    }

    return res.json({
      success: true,
      demo: true,
      user: getSafeUser(user)
    });
  } catch (error) {
    console.error("Demo user lookup error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to load demo account details."
    });
  }
});

// Logout
app.post("/api/auth/logout", (req, res) => {
  clearDemoCookie(res);

  return res.json({
    success: true,
    demo: true,
    message: "Demo logout successful."
  });
});

// ==================== HEALTH CHECK ====================

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    website: "MahaUpdate",
    message: "Website server is running!",
    auth: "demo",
    database: "not-used",
    env: {
      sessionSecret: process.env.SESSION_SECRET
        ? "configured"
        : "missing"
    },
    languages: ["Marathi", "Hindi", "English"]
  });
});

// ==================== NEWS API TEST ====================

app.get("/api/test-news", (req, res) => {
  res.json({
    success: true,
    message: "News route is working!"
  });
});

// ==================== NEWS CATEGORIES ====================

const newsCategories = {
  all: {
    en: "Maharashtra latest news",
    mr: "महाराष्ट्र ताज्या बातम्या",
    hi: "महाराष्ट्र ताजा समाचार"
  },
  maharashtra: {
    en: "Maharashtra news",
    mr: "महाराष्ट्र बातम्या",
    hi: "महाराष्ट्र समाचार"
  },
  national: {
    en: "India national international news",
    mr: "भारत देश विदेश बातम्या",
    hi: "भारत देश विदेश समाचार"
  },
  politics: {
    en: "Maharashtra politics government",
    mr: "महाराष्ट्र राजकारण",
    hi: "महाराष्ट्र राजनीति"
  },
  crime: {
    en: "Maharashtra crime police court",
    mr: "महाराष्ट्र गुन्हेगारी पोलीस बातम्या",
    hi: "महाराष्ट्र अपराध पुलिस समाचार"
  },
  agriculture: {
    en: "Maharashtra agriculture farmers crops",
    mr: "महाराष्ट्र शेती शेतकरी पिके",
    hi: "महाराष्ट्र कृषि किसान फसल"
  },
  education: {
    en: "Maharashtra education schools exams",
    mr: "महाराष्ट्र शिक्षण शाळा परीक्षा",
    hi: "महाराष्ट्र शिक्षा स्कूल परीक्षा"
  },
  jobs: {
    en: "Maharashtra government jobs recruitment",
    mr: "महाराष्ट्र सरकारी भरती नोकरी",
    hi: "महाराष्ट्र सरकारी भर्ती नौकरी"
  },
  schemes: {
    en: "Maharashtra government schemes",
    mr: "महाराष्ट्र सरकारी योजना",
    hi: "महाराष्ट्र सरकारी योजनाएं"
  },
  gr: {
    en: "Maharashtra government resolution GR",
    mr: "महाराष्ट्र शासन निर्णय GR",
    hi: "महाराष्ट्र शासन निर्णय"
  },
  sports: {
    en: "Maharashtra sports news",
    mr: "महाराष्ट्र क्रीडा बातम्या",
    hi: "महाराष्ट्र खेल समाचार"
  },
  entertainment: {
    en: "Marathi cinema entertainment",
    mr: "मराठी चित्रपट मनोरंजन",
    hi: "मराठी फिल्म मनोरंजन"
  },
  business: {
    en: "Maharashtra business economy",
    mr: "महाराष्ट्र व्यापार अर्थव्यवस्था",
    hi: "महाराष्ट्र व्यापार अर्थव्यवस्था"
  },
  weather: {
    en: "Maharashtra weather rainfall",
    mr: "महाराष्ट्र हवामान पाऊस",
    hi: "महाराष्ट्र मौसम बारिश"
  },
  district: {
    en: "Maharashtra district local news",
    mr: "महाराष्ट्र जिल्हा स्थानिक बातम्या",
    hi: "महाराष्ट्र जिला स्थानीय समाचार"
  }
};

// ==================== LANGUAGE SETTINGS ====================

const languageSettings = {
  en: { hl: "en-IN", ceid: "IN:en" },
  mr: { hl: "mr", ceid: "IN:mr" },
  hi: { hl: "hi", ceid: "IN:hi" }
};

// ==================== CATEGORIES API ====================

app.get("/api/categories", (req, res) => {
  const categories = Object.keys(newsCategories).map((id) => ({
    id,
    name: id.charAt(0).toUpperCase() + id.slice(1)
  }));

  res.json(categories);
});

// ==================== RSS PARSER ====================

const parser = new Parser({
  timeout: 20000,
  headers: {
    "User-Agent": "Mozilla/5.0 (compatible; MahaUpdate/1.0)"
  }
});

// ==================== FETCH NEWS ====================

app.get("/api/news", async (req, res) => {
  try {
    const requestedCategory = String(
      req.query.category || "all"
    ).toLowerCase();

    const category = Object.prototype.hasOwnProperty.call(
      newsCategories,
      requestedCategory
    )
      ? requestedCategory
      : "all";

    const requestedLanguage = String(
      req.query.lang || "mr"
    ).toLowerCase();

    const lang = Object.prototype.hasOwnProperty.call(
      languageSettings,
      requestedLanguage
    )
      ? requestedLanguage
      : "mr";

    const query = newsCategories[category][lang];
    const settings = languageSettings[lang];

    const url =
      "https://news.google.com/rss/search?q=" +
      encodeURIComponent(query) +
      "&hl=" + settings.hl +
      "&gl=IN&ceid=" + settings.ceid;

    const data = await parser.parseURL(url);

    const news = (data.items || []).map((item) => ({
      title: item.title || "शीर्षक उपलब्ध नाही",
      link: item.link || "",
      publishedAt: item.isoDate || item.pubDate || null,
      source:
        (item.source && item.source.title) ||
        item.creator ||
        "Google News",
      category,
      language: lang
    }));

    news.sort((a, b) => {
      const dateA = new Date(a.publishedAt || 0).getTime();
      const dateB = new Date(b.publishedAt || 0).getTime();

      return dateB - dateA;
    });

    console.log(
      `Loaded ${news.length} news articles: category=${category}, language=${lang}`
    );

    res.json({
      success: true,
      count: news.length,
      category,
      language: lang,
      news
    });
  } catch (error) {
    console.error("News API error:", error.message);

    res.status(500).json({
      success: false,
      message: "Unable to load news from the news provider."
    });
  }
});

// ==================== START SERVER ====================
// DEMO mode: no database. Local (`npm start`) only needs SESSION_SECRET.
// Vercel: do NOT listen; export `app` via api/index.js.

function startLocalServer() {
  if (!process.env.SESSION_SECRET) {
    console.error("SESSION_SECRET is missing from .env");
    process.exit(1);
  }

  app.listen(PORT, () => {
    console.log(`MahaUpdate (demo auth) running at http://localhost:${PORT}`);
  });
}

if (require.main === module) {
  startLocalServer();
}

module.exports = app;
// Alias for runtimes/bundlers that look for a `.default` export.
module.exports.default = app;