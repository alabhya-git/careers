require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const hpp = require("hpp");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const mongoose = require("mongoose");
const { PORT, CORS_ORIGIN, MONGO_URL } = require("./src/config");
const { ensureDirectories } = require("./src/store");
const {
  ensureDefaultAdminAccount,
  migrateUsersAndCollectionsIfNeeded,
} = require("./src/portal-helpers");
const { registerAuthProfileRoutes } = require("./src/routes/auth-profile");
const { registerOpportunityRoutes } = require("./src/routes/opportunities");
const { registerMessagingRoutes } = require("./src/routes/messaging");
const { registerAdminRoutes } = require("./src/routes/admin");

const app = express();

const baseCorsOptions = {
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

if (CORS_ORIGIN === "*") {
  baseCorsOptions.origin = true;
} else {
  baseCorsOptions.origin = CORS_ORIGIN.split(",").map((item) => item.trim());
}

app.use(cors(baseCorsOptions));
app.use(helmet());
app.use(hpp());
app.use(express.json({ limit: "2mb" }));

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(globalLimiter);
app.use("/api/auth", authLimiter);

app.get("/", (_, res) => {
  res.send("Secure Job Portal Backend Running");
});

app.get("/api/test", (_, res) => {
  res.json({ message: "API working" });
});

registerAuthProfileRoutes(app);
registerOpportunityRoutes(app);
registerMessagingRoutes(app);
registerAdminRoutes(app);

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      res.status(400).json({ message: "Resume file exceeds 5MB limit." });
      return;
    }

    res.status(400).json({ message: err.message });
    return;
  }

  if (err.message === "Only PDF and DOCX files are allowed.") {
    res.status(400).json({ message: err.message });
    return;
  }

  console.error(err);
  res.status(500).json({ message: "Internal server error." });
});

app.use((_, res) => {
  res.status(404).json({ message: "Route not found." });
});

ensureDirectories();

mongoose
  .connect(MONGO_URL)
  .then(async () => {
    console.log("Connected to MongoDB");
    await ensureDefaultAdminAccount();
    await migrateUsersAndCollectionsIfNeeded();
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Backend running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("MongoDB connection error:", err);
  });
