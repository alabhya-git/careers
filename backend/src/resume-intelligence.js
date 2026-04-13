const path = require("path");

const STOP_WORDS = new Set([
  "a",
  "about",
  "an",
  "and",
  "are",
  "as",
  "at",
  "be",
  "by",
  "for",
  "from",
  "in",
  "into",
  "is",
  "of",
  "on",
  "or",
  "that",
  "the",
  "their",
  "to",
  "with",
  "you",
  "your",
  "using",
  "used",
  "use",
  "will",
  "within",
  "across",
  "have",
  "has",
  "had",
  "this",
  "these",
  "those",
  "it",
  "its",
  "i",
  "we",
  "our",
  "ours",
  "they",
  "them",
  "his",
  "her",
  "hers",
  "he",
  "she",
  "my",
  "mine",
  "resume",
  "candidate",
  "professional",
  "experience",
  "work",
  "working",
  "project",
  "projects",
  "skills",
  "summary",
  "role",
  "roles",
  "team",
  "teams",
]);

const SKILL_CATALOG = [
  { name: "JavaScript", patterns: [/\bjavascript\b/, /\becmascript\b/, /\bjs\b/] },
  { name: "TypeScript", patterns: [/\btypescript\b/, /\bts\b/] },
  { name: "React", patterns: [/\breact\b/, /\breact\.js\b/, /\breactjs\b/] },
  { name: "Node.js", patterns: [/\bnode\b/, /\bnode\.js\b/, /\bnodejs\b/] },
  { name: "Express", patterns: [/\bexpress\b/, /\bexpress\.js\b/] },
  { name: "HTML", patterns: [/\bhtml\b/, /\bhtml5\b/] },
  { name: "CSS", patterns: [/\bcss\b/, /\bcss3\b/, /\bsass\b/, /\bscss\b/] },
  { name: "Python", patterns: [/\bpython\b/] },
  { name: "FastAPI", patterns: [/\bfastapi\b/] },
  { name: "Django", patterns: [/\bdjango\b/] },
  { name: "Java", patterns: [/\bjava\b/] },
  { name: "Spring Boot", patterns: [/\bspring boot\b/, /\bspringboot\b/] },
  { name: "C++", patterns: [/\bc\+\+\b/] },
  { name: "C", patterns: [/\bc language\b/, /\bansi c\b/, /\bc programming\b/] },
  { name: "SQL", patterns: [/\bsql\b/, /\bstructured query language\b/] },
  { name: "PostgreSQL", patterns: [/\bpostgresql\b/, /\bpostgres\b/] },
  { name: "MySQL", patterns: [/\bmysql\b/] },
  { name: "MongoDB", patterns: [/\bmongodb\b/, /\bmongo\b/] },
  { name: "REST APIs", patterns: [/\brest api\b/, /\brestful\b/, /\bapi development\b/] },
  { name: "GraphQL", patterns: [/\bgraphql\b/] },
  { name: "AWS", patterns: [/\baws\b/, /\bamazon web services\b/] },
  { name: "Azure", patterns: [/\bazure\b/] },
  { name: "Docker", patterns: [/\bdocker\b/] },
  { name: "Kubernetes", patterns: [/\bkubernetes\b/, /\bk8s\b/] },
  { name: "Git", patterns: [/\bgit\b/, /\bgithub\b/, /\bgitlab\b/] },
  { name: "CI/CD", patterns: [/\bci\/cd\b/, /\bcontinuous integration\b/, /\bcontinuous delivery\b/] },
  { name: "Linux", patterns: [/\blinux\b/, /\bubuntu\b/] },
  { name: "Nginx", patterns: [/\bnginx\b/] },
  { name: "JWT", patterns: [/\bjwt\b/, /\bjson web token\b/] },
  { name: "PKI", patterns: [/\bpki\b/, /\bpublic key infrastructure\b/] },
  { name: "Cryptography", patterns: [/\bcryptography\b/, /\bencryption\b/, /\bdecryption\b/] },
  { name: "Cybersecurity", patterns: [/\bcybersecurity\b/, /\bsecurity\b/, /\binformation security\b/] },
  { name: "Penetration Testing", patterns: [/\bpenetration testing\b/, /\bpen testing\b/, /\bpentest\b/] },
  { name: "OWASP", patterns: [/\bowasp\b/, /\bxss\b/, /\bcsrf\b/, /\bsql injection\b/] },
  { name: "Machine Learning", patterns: [/\bmachine learning\b/, /\bml\b/] },
  { name: "Data Analysis", patterns: [/\bdata analysis\b/, /\bdata analytics\b/, /\bpandas\b/] },
  { name: "Communication", patterns: [/\bcommunication\b/, /\bpresentation\b/] },
  { name: "Leadership", patterns: [/\bleadership\b/, /\blead\b/, /\bmentor\b/] },
];

function normalizeWhitespace(value) {
  return String(value || "").replace(/\0/g, " ").replace(/\s+/g, " ").trim();
}

function normalizeToken(value) {
  return normalizeWhitespace(value)
    .toLowerCase()
    .replace(/[^a-z0-9+.#/-]+/g, " ")
    .trim();
}

function titleCaseFromToken(value) {
  return normalizeWhitespace(value)
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function uniqueStrings(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

function tokenize(value) {
  return normalizeToken(value)
    .split(/\s+/)
    .map((item) => item.trim())
    .filter(
      (item) =>
        item &&
        item.length > 2 &&
        !STOP_WORDS.has(item) &&
        !/^\d+$/.test(item)
    );
}

function detectCanonicalSkills(value) {
  const normalized = normalizeToken(value);
  if (!normalized) {
    return [];
  }

  return SKILL_CATALOG.filter((skill) =>
    skill.patterns.some((pattern) => pattern.test(normalized))
  ).map((skill) => skill.name);
}

function normalizeSkillForMatching(value) {
  const canonical = detectCanonicalSkills(value);
  if (canonical.length) {
    return canonical.map((item) => item.toLowerCase());
  }

  const normalized = normalizeToken(value);
  return normalized ? [normalized] : [];
}

function extractSkillsFromText(text) {
  return uniqueStrings(
    SKILL_CATALOG.filter((skill) =>
      skill.patterns.some((pattern) => pattern.test(text))
    ).map((skill) => skill.name)
  );
}

function extractYearsOfExperience(text) {
  const matches = Array.from(
    normalizeWhitespace(text).matchAll(
      /(\d{1,2})\s*\+?\s*(?:years?|yrs?)(?:\s+of)?\s+experience/gi
    )
  );
  if (!matches.length) {
    return null;
  }

  return matches.reduce((maxYears, match) => {
    const parsed = Number(match[1]);
    return Number.isFinite(parsed) ? Math.max(maxYears, parsed) : maxYears;
  }, 0);
}

function detectSections(text) {
  const normalized = normalizeToken(text);
  const possibleSections = [
    "summary",
    "skills",
    "education",
    "experience",
    "projects",
    "certifications",
    "achievements",
    "internships",
  ];

  return possibleSections.filter((section) => normalized.includes(section));
}

function extractTopKeywords(text, extractedSkills) {
  const skillTokens = new Set(
    extractedSkills.flatMap((skill) => tokenize(skill))
  );
  const counts = new Map();

  tokenize(text).forEach((token) => {
    if (skillTokens.has(token)) {
      return;
    }
    counts.set(token, (counts.get(token) || 0) + 1);
  });

  return Array.from(counts.entries())
    .sort((left, right) => {
      if (right[1] !== left[1]) {
        return right[1] - left[1];
      }
      return left[0].localeCompare(right[0]);
    })
    .slice(0, 12)
    .map(([token]) => titleCaseFromToken(token));
}

function buildAnalysisSummary(extractedSkills, topKeywords, yearsOfExperience) {
  const fragments = [];

  if (extractedSkills.length) {
    fragments.push(`skills: ${extractedSkills.slice(0, 6).join(", ")}`);
  }
  if (topKeywords.length) {
    fragments.push(`keywords: ${topKeywords.slice(0, 5).join(", ")}`);
  }
  if (yearsOfExperience !== null) {
    fragments.push(`experience signal: ${yearsOfExperience}+ years`);
  }

  return fragments.join(" | ");
}

function buildResumeAnalysisFromText(text, metadata = {}) {
  const normalizedText = normalizeWhitespace(text);
  const extractedSkills = extractSkillsFromText(normalizedText.toLowerCase());
  const topKeywords = extractTopKeywords(normalizedText, extractedSkills);
  const yearsOfExperience = extractYearsOfExperience(normalizedText);
  const wordCount = normalizedText ? normalizedText.split(/\s+/).length : 0;
  const sectionsDetected = detectSections(normalizedText);

  return {
    parseStatus: normalizedText ? "parsed" : "empty",
    parsedAt: new Date().toISOString(),
    parser: metadata.parser || "unknown",
    pageCount:
      Number.isFinite(Number(metadata.pageCount)) && Number(metadata.pageCount) > 0
        ? Number(metadata.pageCount)
        : null,
    wordCount,
    extractedSkills,
    topKeywords,
    yearsOfExperience,
    sectionsDetected,
    summary: buildAnalysisSummary(
      extractedSkills,
      topKeywords,
      yearsOfExperience
    ),
  };
}

async function extractTextFromResume(file) {
  const extension = path.extname(file?.originalName || "").toLowerCase();
  const mimeType = String(file?.mimeType || "").toLowerCase();

  if (extension === ".pdf" || mimeType === "application/pdf") {
    const { PDFParse } = require("pdf-parse");
    const parser = new PDFParse({ data: file.buffer });

    try {
      const parsed = await parser.getText();
      return {
        parser: "pdf-parse",
        pageCount: parsed.total || null,
        text: parsed.text || "",
      };
    } finally {
      await parser.destroy();
    }
  }

  if (
    extension === ".docx" ||
    mimeType ===
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
  ) {
    const mammoth = require("mammoth");
    const parsed = await mammoth.extractRawText({ buffer: file.buffer });
    return {
      parser: "mammoth",
      pageCount: null,
      text: parsed.value || "",
    };
  }

  throw new Error("Unsupported resume type for parsing.");
}

async function analyzeResumeFile(file) {
  try {
    const extracted = await extractTextFromResume(file);
    return buildResumeAnalysisFromText(extracted.text, extracted);
  } catch (error) {
    return {
      parseStatus: "failed",
      parsedAt: new Date().toISOString(),
      parser: "unavailable",
      pageCount: null,
      wordCount: 0,
      extractedSkills: [],
      topKeywords: [],
      yearsOfExperience: null,
      sectionsDetected: [],
      summary: "",
      parseWarning:
        "Resume uploaded securely, but text extraction was unavailable for matching.",
      parseError: error.message,
    };
  }
}

function buildCandidateMatchProfile(user) {
  const resumeAnalysis = user?.resume?.analysis || {};
  const resumeSkills = Array.isArray(resumeAnalysis.extractedSkills)
    ? resumeAnalysis.extractedSkills
    : [];
  const profileSkills = Array.isArray(user?.profile?.skills) ? user.profile.skills : [];
  const candidateSkills = uniqueStrings([...resumeSkills, ...profileSkills]);
  const skillSet = new Set(
    candidateSkills.flatMap((skill) => normalizeSkillForMatching(skill))
  );

  const keywordSet = new Set([
    ...tokenize(resumeAnalysis.summary || ""),
    ...tokenize((resumeAnalysis.topKeywords || []).join(" ")),
    ...tokenize(user?.profile?.headline || ""),
    ...tokenize(user?.profile?.bio || ""),
    ...tokenize(profileSkills.join(" ")),
  ]);

  return {
    isReady: Boolean(candidateSkills.length || keywordSet.size),
    yearsOfExperience:
      resumeAnalysis.yearsOfExperience === null ||
      resumeAnalysis.yearsOfExperience === undefined
        ? null
        : Number.isFinite(Number(resumeAnalysis.yearsOfExperience)) &&
            Number(resumeAnalysis.yearsOfExperience) >= 0
          ? Number(resumeAnalysis.yearsOfExperience)
          : null,
    candidateSkills,
    skillSet,
    keywordSet,
  };
}

function buildJobKeywordSignals(job, company) {
  const skillSignals = uniqueStrings(
    Array.isArray(job?.requiredSkills) ? job.requiredSkills : []
  );
  const keywordSignals = uniqueStrings(
    tokenize(
      [
        job?.title || "",
        job?.description || "",
        job?.location || "",
        company?.name || "",
        skillSignals.join(" "),
      ].join(" ")
    )
  );

  return {
    skillSignals,
    keywordSignals,
    yearsRequired: extractYearsOfExperience(
      `${job?.title || ""} ${job?.description || ""}`
    ),
  };
}

function buildJobMatchInsight(job, user, company = null) {
  const candidate = buildCandidateMatchProfile(user);
  if (!candidate.isReady) {
    return null;
  }

  const { skillSignals, keywordSignals, yearsRequired } = buildJobKeywordSignals(
    job,
    company
  );

  const matchedSkills = [];
  const missingSkills = [];
  skillSignals.forEach((skill) => {
    const matches = normalizeSkillForMatching(skill).some((variant) =>
      candidate.skillSet.has(variant)
    );
    if (matches) {
      matchedSkills.push(skill);
    } else {
      missingSkills.push(skill);
    }
  });

  const keywordHits = keywordSignals.filter(
    (keyword) =>
      candidate.keywordSet.has(keyword) || candidate.skillSet.has(keyword)
  );

  const requiredSkillScore = skillSignals.length
    ? (matchedSkills.length / skillSignals.length) * 70
    : candidate.candidateSkills.length
      ? 30
      : 0;
  const keywordScore = keywordSignals.length
    ? (Math.min(keywordHits.length, 6) / Math.min(keywordSignals.length, 6)) * 20
    : 0;

  let experienceScore = 0;
  if (yearsRequired !== null) {
    if (
      candidate.yearsOfExperience !== null &&
      candidate.yearsOfExperience >= yearsRequired
    ) {
      experienceScore = 10;
    } else if (candidate.yearsOfExperience !== null) {
      experienceScore = 4;
    }
  } else if (candidate.yearsOfExperience !== null) {
    experienceScore = 6;
  }

  const score = Math.min(
    100,
    Math.max(0, Math.round(requiredSkillScore + keywordScore + experienceScore))
  );
  const band =
    score >= 80 ? "Strong" : score >= 60 ? "Good" : score >= 40 ? "Potential" : "Low";
  const explanation = [];

  if (skillSignals.length) {
    explanation.push(
      `Matched ${matchedSkills.length}/${skillSignals.length} required skills`
    );
  }
  if (keywordHits.length) {
    explanation.push(`Keyword overlap: ${keywordHits.slice(0, 4).join(", ")}`);
  }
  if (yearsRequired !== null) {
    explanation.push(
      candidate.yearsOfExperience !== null &&
        candidate.yearsOfExperience >= yearsRequired
        ? `Meets ${yearsRequired}+ years experience signal`
        : `Job mentions ${yearsRequired}+ years experience`
    );
  }

  return {
    score,
    band,
    matchedSkills,
    missingSkills,
    keywordHits: keywordHits.slice(0, 6).map((item) => titleCaseFromToken(item)),
    candidateYearsOfExperience: candidate.yearsOfExperience,
    yearsRequired,
    explanation,
  };
}

module.exports = {
  analyzeResumeFile,
  buildResumeAnalysisFromText,
  buildJobMatchInsight,
  buildCandidateMatchProfile,
};
