const fs = require("fs");
const {
  DATA_DIR,
  STORAGE_DIR,
  RESUME_DIR,
  DB_FILE,
} = require("./config");

const DEFAULT_DB = {
  users: [],
  companies: [],
  jobs: [],
  applications: [],
  conversations: [],
  auditLogs: [],
};

function normalizeDb(parsed) {
  return {
    users: Array.isArray(parsed?.users) ? parsed.users : [],
    companies: Array.isArray(parsed?.companies) ? parsed.companies : [],
    jobs: Array.isArray(parsed?.jobs) ? parsed.jobs : [],
    applications: Array.isArray(parsed?.applications) ? parsed.applications : [],
    conversations: Array.isArray(parsed?.conversations) ? parsed.conversations : [],
    auditLogs: Array.isArray(parsed?.auditLogs) ? parsed.auditLogs : [],
  };
}

function ensureDirectories() {
  [DATA_DIR, STORAGE_DIR, RESUME_DIR].forEach((dir) => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });

  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify(DEFAULT_DB, null, 2), "utf8");
  }
}

function readDb() {
  ensureDirectories();
  try {
    const raw = fs.readFileSync(DB_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return normalizeDb(parsed);
  } catch (error) {
    fs.writeFileSync(DB_FILE, JSON.stringify(DEFAULT_DB, null, 2), "utf8");
    return normalizeDb(DEFAULT_DB);
  }
}

function writeDb(db) {
  ensureDirectories();
  fs.writeFileSync(DB_FILE, JSON.stringify(normalizeDb(db), null, 2), "utf8");
}

module.exports = {
  ensureDirectories,
  readDb,
  writeDb,
};
