
const express = require("express");
const path = require("path");
const Parser = require("rss-parser");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    website: "MahaUpdate",
    message: "Website server is running!",
    languages: ["Marathi", "Hindi", "English"]
  });
});

// News API test
app.get("/api/test-news", (req, res) => {
  res.json({
    success: true,
    message: "News route is working!"
  });
});

// News categories in Marathi, Hindi and English
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
    mr: "Maharashtra क्रीडा बातम्या",
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

// Google News language settings
const languageSettings = {
  en: { hl: "en-IN", ceid: "IN:en" },
  mr: { hl: "mr", ceid: "IN:mr" },
  hi: { hl: "hi", ceid: "IN:hi" }
};

// Categories API
app.get("/api/categories", (req, res) => {
  const categories = Object.keys(newsCategories).map((id) => ({
    id,
    name: id.charAt(0).toUpperCase() + id.slice(1)
  }));

  res.json(categories);
});

// RSS parser
const parser = new Parser({
  timeout: 20000,
  headers: {
    "User-Agent": "Mozilla/5.0 (compatible; MahaUpdate/1.0)"
  }
});

// Fetch news by category and language
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
    console.error("News API error:", error);

    res.status(500).json({
      success: false,
      message: "Unable to load news from the news provider.",
      error: error.message
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`MahaUpdate running at http://localhost:${PORT}`);
});