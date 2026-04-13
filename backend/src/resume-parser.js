const pdf = require("pdf-parse");
const mammoth = require("mammoth");

/**
 * Normalizes text by removing special characters, converting to lowercase, 
 * and splitting into tokens.
 * @param {string} text 
 * @returns {string[]} tokens
 */
function tokenize(text) {
  if (!text) return [];
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/)
    .filter((token) => token.length > 2);
}

/**
 * Extracts plain text from a resume buffer based on MIME type.
 * @param {Buffer} buffer 
 * @param {string} mimeType 
 * @returns {Promise<string>}
 */
async function extractTextFromBuffer(buffer, mimeType) {
  try {
    if (mimeType === "application/pdf") {
      const data = await pdf(buffer);
      return data.text || "";
    } else if (
      mimeType === "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    ) {
      const result = await mammoth.extractRawText({ buffer });
      return result.value || "";
    }
    return "";
  } catch (error) {
    console.error("Resume parsing error:", error);
    return "";
  }
}

module.exports = {
  extractTextFromBuffer,
  tokenize,
};
