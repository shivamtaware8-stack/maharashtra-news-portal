const express = require("express");
const path = require("path");
const Parser = require("rss-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const MongoStore = require("connect-mongo").MongoStore;
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

// ==================== USER MODEL ====================

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 80
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      maxlength: 254
    },

    password: {
      type: String,
      required: true,
      select: false
    }
  },
  {
    timestamps: true
  }
);

const User =
  mongoose.models.User ||
  mongoose.model("User", userSchema);

// ==================== SESSION CONFIGURATION ====================
// NOTE: Never exit the process at import time. On Vercel (serverless) a
// top-level process.exit() turns into a generic HTTP 500 with no useful log.
// Validate env vars, log a clear message (never the secret value), and keep
// public routes (/api/health, /api/news, frontend) working even when the DB
// is not configured. DB-backed routes return 503 with a clear message.

const hasSessionSecret = Boolean(process.env.SESSION_SECRET);
const hasMongoUri = Boolean(process.env.MONGODB_URI);

if (!hasSessionSecret) {
  console.error(
    "SESSION_SECRET is missing. Set it in .env (local) and in Vercel Project -> Settings -> Environment Variables (Production)."
  );
}

if (!hasMongoUri) {
  console.error(
    "MONGODB_URI is missing. Set it in .env (local) and in Vercel Project -> Settings -> Environment Variables (Production)."
  );
}

app.set("trust proxy", 1);

// Reuse one cached mongoose connection across serverless invocations.
let cachedDbPromise = global.__mahaupdateDbPromise || null;

function connectDb() {
  if (mongoose.connection.readyState === 1) {
    return Promise.resolve(mongoose);
  }

  if (!cachedDbPromise) {
    cachedDbPromise = mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 8000
    });
    global.__mahaupdateDbPromise = cachedDbPromise;

    cachedDbPromise.then(
      () => console.log("MongoDB connected successfully"),
      (error) => {
        cachedDbPromise = null;
        global.__mahaupdateDbPromise = null;
        console.error("MongoDB connection failed:", error.message);
      }
    );
  }

  return cachedDbPromise;
}

function createSessionStore() {
  if (!hasMongoUri) {
    return undefined;
  }

  try {
    // mongoUrl mode connects LAZILY (only on first session read/write),
    // so requiring this file never opens a DB connection at import time.
    // (An eager clientPromise here crashed the serverless function on boot.)
    return MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      collectionName: "sessions",
      ttl: 7 * 24 * 60 * 60
    });
  } catch (error) {
    console.error("Session store init failed:", error.message);
    return undefined;
  }
}

const sessionMiddleware = session({
  name: "mahaupdate.sid",
  // Fallback keeps the app bootable so /api/health explains the problem
  // instead of crashing with HTTP 500. Production MUST set a real secret.
  secret:
    process.env.SESSION_SECRET || "mahaupdate-local-dev-only-change-me",
  resave: false,
  saveUninitialized: false,
  proxy: true,

  store: createSessionStore(),

  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
});

app.use(sessionMiddleware);

// Block only DB-backed routes when the DB is not configured, instead of
// crashing the whole function.
async function ensureDb(req, res, next) {
  if (!process.env.MONGODB_URI) {
    return res.status(503).json({
      success: false,
      message: "Database is not configured (MONGODB_URI missing)."
    });
  }

  if (!process.env.SESSION_SECRET) {
    return res.status(500).json({
      success: false,
      message: "Server session is not configured (SESSION_SECRET missing)."
    });
  }

  try {
    await connectDb();
    return next();
  } catch (error) {
    console.error("MongoDB connection failed:", error.message);

    return res.status(503).json({
      success: false,
      message: "Database unavailable. Please try again."
    });
  }
}

// ==================== AUTH HELPERS ====================

function getSafeUser(user) {
  return {
    id: user._id.toString(),
    name: user.name,
    email: user.email
  };
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      success: false,
      message: "Please log in first."
    });
  }

  next();
}

// ==================== AUTH API ====================

// Register
app.post("/api/auth/register", ensureDb, async (req, res) => {
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

    const existingUser = await User.findOne({ email })
      .select("_id")
      .lean();

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists."
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      name,
      email,
      password: hashedPassword
    });

    // Regenerate the session after account creation.
    req.session.regenerate((sessionError) => {
      if (sessionError) {
        console.error("Session error:", sessionError.message);

        return res.status(500).json({
          success: false,
          message: "Account created, but login failed. Please log in."
        });
      }

      req.session.userId = user._id.toString();

      req.session.save((saveError) => {
        if (saveError) {
          console.error("Session save error:", saveError.message);

          return res.status(500).json({
            success: false,
            message: "Account created, but login failed. Please log in."
          });
        }

        return res.status(201).json({
          success: true,
          message: "Registration successful.",
          user: getSafeUser(user)
        });
      });
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists."
      });
    }

    console.error("Registration error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Registration failed. Please try again."
    });
  }
});

// Login
app.post("/api/auth/login", ensureDb, async (req, res) => {
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

    const user = await User.findOne({ email })
      .select("+password");

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordMatches) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    // Regenerate the session to reduce session-fixation risk.
    req.session.regenerate((sessionError) => {
      if (sessionError) {
        console.error("Session error:", sessionError.message);

        return res.status(500).json({
          success: false,
          message: "Unable to log in. Please try again."
        });
      }

      req.session.userId = user._id.toString();

      req.session.save((saveError) => {
        if (saveError) {
          console.error("Session save error:", saveError.message);

          return res.status(500).json({
            success: false,
            message: "Unable to log in. Please try again."
          });
        }

        return res.json({
          success: true,
          message: "Login successful.",
          user: getSafeUser(user)
        });
      });
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Login failed. Please try again."
    });
  }
});

// Get current logged-in user
app.get("/api/auth/me", ensureDb, requireLogin, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId)
      .select("name email");

    if (!user) {
      return req.session.destroy(() => {
        res.status(401).json({
          success: false,
          message: "User account not found. Please log in again."
        });
      });
    }

    return res.json({
      success: true,
      user: getSafeUser(user)
    });
  } catch (error) {
    console.error("User lookup error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to load account details."
    });
  }
});

// Logout
app.post("/api/auth/logout", (req, res) => {
  if (!req.session) {
    return res.json({
      success: true,
      message: "Logged out."
    });
  }

  req.session.destroy((error) => {
    if (error) {
      console.error("Logout error:", error.message);

      return res.status(500).json({
        success: false,
        message: "Unable to log out. Please try again."
      });
    }

    res.clearCookie("mahaupdate.sid", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax"
    });

    return res.json({
      success: true,
      message: "Logout successful."
    });
  });
});

// ==================== HEALTH CHECK ====================

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    website: "MahaUpdate",
    message: "Website server is running!",
    database:
      mongoose.connection.readyState === 1
        ? "connected"
        : "disconnected",
    env: {
      mongodbUri: process.env.MONGODB_URI ? "configured" : "missing",
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
// Local: connect to MongoDB, then listen on PORT.
// Vercel: do NOT listen; export `app` and connect lazily per request.

async function startLocalServer() {
  if (!process.env.MONGODB_URI) {
    console.error("MONGODB_URI is missing from .env");
    process.exit(1);
  }

  if (!process.env.SESSION_SECRET) {
    console.error("SESSION_SECRET is missing from .env");
    process.exit(1);
  }

  try {
    await connectDb();

    app.listen(PORT, () => {
      console.log(`MahaUpdate running at http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("MongoDB connection failed:", error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  startLocalServer();
}

module.exports = app;
// Alias for runtimes/bundlers that look for a `.default` export.
module.exports.default = app;