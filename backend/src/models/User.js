const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
    totp: { type: mongoose.Schema.Types.Mixed, default: {} },
    messaging: { type: mongoose.Schema.Types.Mixed, default: {} },
    profile: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  { strict: false, timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
