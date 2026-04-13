const { tokenize } = require("./resume-parser");

/**
 * Calculates a match score and identifies matching keywords between a resume and job data.
 * @param {string} resumeText 
 * @param {Object} jobData { title, description, requiredSkills }
 * @returns {Object} { score, matchedKeywords }
 */
function calculateMatchScore(resumeText, jobData) {
  if (!resumeText) return { score: 0, matchedKeywords: [] };

  const resumeTokens = new Set(tokenize(resumeText));
  
  // Combine all job-related text for a broad keyword match
  const jobTitleTokens = tokenize(jobData.title || "");
  const jobDescTokens = tokenize(jobData.description || "");
  const jobSkillsTokens = Array.isArray(jobData.requiredSkills) 
    ? jobData.requiredSkills.flatMap(s => tokenize(s))
    : tokenize(String(jobData.requiredSkills || ""));

  // Significant tokens from job
  const importantTokens = new Set([...jobTitleTokens, ...jobSkillsTokens]);
  const allJobTokens = new Set([...importantTokens, ...jobDescTokens]);

  const matchedKeywordsSet = new Set();
  
  // Find intersection
  let matchCount = 0;
  allJobTokens.forEach((token) => {
    if (resumeTokens.has(token)) {
      matchCount++;
      // Only include "important" keywords in the matched list to avoid noise
      if (importantTokens.has(token) || token.length > 4) {
        matchedKeywordsSet.add(token);
      }
    }
  });

  // Calculate Jaccard-like score with basic weighting
  // Score = (Intersection Size) / (Total Unique Job Tokens)
  // We can weight title and skills higher by adding them to the intersection count again
  let weightedMatchCount = matchCount;
  importantTokens.forEach((token) => {
    if (resumeTokens.has(token)) {
      weightedMatchCount += 0.5; // Extra weight for title/skills
    }
  });

  const divisor = allJobTokens.size || 1;
  const rawScore = (weightedMatchCount / divisor) * 100;
  
  // Cap at 100
  const score = Math.min(Math.round(rawScore), 100);

  return {
    score,
    matchedKeywords: Array.from(matchedKeywordsSet).slice(0, 10), // Limit to top 10
  };
}

module.exports = {
  calculateMatchScore,
};
