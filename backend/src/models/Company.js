const mongoose = require("mongoose");

const companySchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
  },
  { strict: false, timestamps: true }
);

module.exports = mongoose.model("Company", companySchema);
