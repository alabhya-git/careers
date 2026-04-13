require("dotenv").config();
const fs = require("fs");
const path = require("path");
const mongoose = require("mongoose");
const { MONGO_URL, DB_FILE } = require("../src/config");

const User = require("../src/models/User");
const Company = require("../src/models/Company");
const Job = require("../src/models/Job");
const Application = require("../src/models/Application");
const Conversation = require("../src/models/Conversation");
const AuditLog = require("../src/models/AuditLog");

async function migrate() {
  try {
    console.log("Connecting to MongoDB...");
    await mongoose.connect(MONGO_URL);
    console.log("Connected.");

    if (!fs.existsSync(DB_FILE)) {
      console.log("No db.json found. Skipping migration.");
      process.exit(0);
    }

    const db = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));

    const collections = [
      { name: "users", model: User },
      { name: "companies", model: Company },
      { name: "jobs", model: Job },
      { name: "applications", model: Application },
      { name: "conversations", model: Conversation },
      { name: "auditLogs", model: AuditLog },
    ];

    for (const { name, model } of collections) {
      const data = db[name] || [];
      if (data.length > 0) {
        console.log(`Migrating ${data.length} items to ${name}...`);
        await model.deleteMany({}); // Clear existing data to avoid duplicates on UUIDs
        await model.insertMany(data);
        console.log(`Done.`);
      } else {
        console.log(`No data for ${name}.`);
      }
    }

    console.log("Migration completed successfully.");
    process.exit(0);
  } catch (error) {
    console.error("Migration failed:", error);
    process.exit(1);
  }
}

migrate();
