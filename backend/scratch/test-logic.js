const { extractTextFromBuffer, tokenize } = require("../src/resume-parser");
const { calculateMatchScore } = require("../src/matcher");
const fs = require("fs");
const path = require("path");

async function runTest() {
  console.log("--- Testing Matcher ---");
  const sampleResume = `
    Experienced Software Engineer with 5 years in React, Node.js, and AWS.
    Proficient in JavaScript, TypeScript, and SQL.
    Worked on high-scale distributed systems and cloud infrastructure.
  `;
  
  const sampleJob = {
    title: "Senior Full Stack Developer",
    description: "We are looking for a developer with expertise in React and Node.js. Experience with AWS and cloud systems is a plus.",
    requiredSkills: ["React", "Node.js", "JavaScript", "AWS"]
  };

  const match = calculateMatchScore(sampleResume, sampleJob);
  console.log("Match Score:", match.score);
  console.log("Matched Keywords:", match.matchedKeywords);

  if (match.score > 50 && match.matchedKeywords.includes("react")) {
    console.log("✅ Matcher calculation looks correct.");
  } else {
    console.log("❌ Matcher calculation might be off.");
  }

  console.log("\n--- Testing Tokenizer ---");
  const tokens = tokenize("Hello World! This is a test.");
  console.log("Tokens:", tokens);
  if (tokens.includes("hello") && tokens.includes("world")) {
    console.log("✅ Tokenizer looks correct.");
  }

  console.log("\nTest Finished.");
}

runTest().catch(console.error);
