const mongoose = require("mongoose");

const conversationSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
  },
  { strict: false, timestamps: true }
);

module.exports = mongoose.model("Conversation", conversationSchema);
