const { v4: uuidv4 } = require("uuid");
const { appendAuditLog } = require("../audit");
const User = require("../models/User");
const Company = require("../models/Company");
const Job = require("../models/Job");
const Application = require("../models/Application");
const {
  JOB_WORKPLACE_TYPES,
  JOB_EMPLOYMENT_TYPES,
  JOB_STATUSES,
  APPLICATION_STATUSES,
  sanitizeText,
  sanitizeMultilineText,
  sanitizeUrl,
  parseDateInput,
  parseOptionalCurrency,
  parseIdList,
  parseSkills,
  isDeadlinePassed,
  directoryUserPreview,
  getCompanyById,
  getJobById,
  getApplicationById,
  getManagedCompanyIds,
  canManageCompany,
  createUniqueCompanySlug,
  serializeCompany,
  serializeJob,
  serializeApplication,
  requireAuth,
  requireRole,
} = require("../portal-helpers");

function registerOpportunityRoutes(app) {
  app.get("/api/companies", async (req, res) => {
    const queryTerm = sanitizeText(req.query.q || "", 120).toLowerCase();

    let companies;
    if (queryTerm) {
      companies = await Company.find({
        $or: [
          { name: { $regex: queryTerm, $options: "i" } },
          { description: { $regex: queryTerm, $options: "i" } },
          { location: { $regex: queryTerm, $options: "i" } },
        ],
      }).sort({ updatedAt: -1, createdAt: -1 });
    } else {
      companies = await Company.find({}).sort({ updatedAt: -1, createdAt: -1 });
    }

    const serializedCompanies = await Promise.all(
      companies.map((company) => serializeCompany(company))
    );

    res.json({ companies: serializedCompanies });
  });

  app.get("/api/companies/mine", requireAuth, requireRole(["recruiter", "admin"]), async (req, res) => {
    const actor = await User.findOne({ id: req.auth.userId });
    const managedCompanyIds = await getManagedCompanyIds(actor);
    
    const companies = await Company.find({ id: { $in: managedCompanyIds } }).sort({ updatedAt: -1, createdAt: -1 });
    
    const serializedCompanies = await Promise.all(
      companies.map(async (company) => {
        const jobs = await Job.find({ companyId: company.id }).sort({ updatedAt: -1, createdAt: -1 });
        const serializedJobs = await Promise.all(
          jobs.map((job) => serializeJob(job, actor))
        );
        return {
          ...(await serializeCompany(company, actor)),
          jobs: serializedJobs,
        };
      })
    );

    res.json({ companies: serializedCompanies });
  });

  app.post("/api/companies", requireAuth, requireRole(["recruiter", "admin"]), async (req, res) => {
    const name = sanitizeText(req.body.name, 120);
    const description = sanitizeMultilineText(req.body.description, 1200);
    const location = sanitizeText(req.body.location, 120);
    const website = sanitizeUrl(req.body.website);
    const adminUserIdsInput = parseIdList(req.body.adminUserIds);
    const adminUserIds = Array.from(
      new Set([req.auth.userId, ...adminUserIdsInput])
    );

    if (!name || !description || !location || !website) {
      res.status(400).json({
        message: "name, description, location, and a valid website are required.",
      });
      return;
    }

    for (const userId of adminUserIds) {
      const candidate = await User.findOne({ id: userId });
      if (!candidate || !["recruiter", "admin"].includes(candidate.role)) {
        res.status(400).json({
          message: `User ${userId} cannot be a company admin. All company admins must be recruiter or admin accounts.`,
        });
        return;
      }
    }

    const timestamp = new Date().toISOString();
    const company = new Company({
      id: uuidv4(),
      slug: await createUniqueCompanySlug(name),
      name,
      description,
      location,
      website,
      createdByUserId: req.auth.userId,
      adminUserIds,
      createdAt: timestamp,
      updatedAt: timestamp,
    });

    await company.save();
    await appendAuditLog({
      actorUserId: req.auth.userId,
      action: "COMPANY_CREATED",
      targetUserId: req.auth.userId,
      metadata: { companyId: company.id, companyName: company.name },
    });

    const actor = await User.findOne({ id: req.auth.userId });
    res.status(201).json({
      message: "Company page created.",
      company: await serializeCompany(company, actor),
    });
  });

  app.patch("/api/companies/:companyId", requireAuth, requireRole(["recruiter", "admin"]), async (req, res) => {
    const actor = await User.findOne({ id: req.auth.userId });
    const company = await getCompanyById(sanitizeText(req.params.companyId, 80));
    if (!company) {
      res.status(404).json({ message: "Company not found." });
      return;
    }
    if (!canManageCompany(actor, company)) {
      res.status(403).json({ message: "You cannot manage this company." });
      return;
    }

    if (typeof req.body.name === "string") {
      company.name = sanitizeText(req.body.name, 120);
      company.slug = await createUniqueCompanySlug(company.name, company.id);
    }
    if (typeof req.body.description === "string") company.description = sanitizeMultilineText(req.body.description, 1200);
    if (typeof req.body.location === "string") company.location = sanitizeText(req.body.location, 120);
    if (typeof req.body.website === "string") {
      const website = sanitizeUrl(req.body.website);
      if (!website) {
        res.status(400).json({ message: "Provide a valid company website." });
        return;
      }
      company.website = website;
    }
    if (req.body.adminUserIds !== undefined) {
      const nextAdminUserIds = Array.from(
        new Set([company.createdByUserId, ...parseIdList(req.body.adminUserIds)].filter(Boolean))
      );
      for (const userId of nextAdminUserIds) {
        const candidate = await User.findOne({ id: userId });
        if (!candidate || !["recruiter", "admin"].includes(candidate.role)) {
          res.status(400).json({
            message: `User ${userId} cannot be a company admin. All company admins must be recruiter or admin accounts.`,
          });
          return;
        }
      }
      company.adminUserIds = nextAdminUserIds;
    }

    company.updatedAt = new Date().toISOString();
    await appendAuditLog({
      actorUserId: actor.id,
      action: "COMPANY_UPDATED",
      targetUserId: actor.id,
      metadata: { companyId: company.id, fields: Object.keys(req.body || {}) },
    });
    await company.save();

    res.json({
      message: "Company updated.",
      company: await serializeCompany(company, actor),
    });
  });

  app.get("/api/companies/:companyId", async (req, res) => {
    const company = await getCompanyById(sanitizeText(req.params.companyId, 80));
    if (!company) {
      res.status(404).json({ message: "Company not found." });
      return;
    }

    const jobs = await Job.find({
      companyId: company.id,
      status: "open",
    });
    
    const validJobs = jobs.filter(job => !isDeadlinePassed(job.applicationDeadline));
    const serializedJobs = await Promise.all(
      validJobs.map((job) => serializeJob(job))
    );

    res.json({
      company: await serializeCompany(company),
      jobs: serializedJobs,
    });
  });

  app.get("/api/jobs", async (req, res) => {
    const queryTerm = sanitizeText(req.query.q || "", 120).toLowerCase();
    const companyFilter = sanitizeText(req.query.company || "", 120).toLowerCase();
    const locationFilter = sanitizeText(req.query.location || "", 120).toLowerCase();
    const skillFilter = sanitizeText(req.query.skill || "", 40).toLowerCase();
    const workplaceType = sanitizeText(req.query.workplaceType || "", 40).toLowerCase();
    const employmentType = sanitizeText(req.query.employmentType || "", 40).toLowerCase();

    let query = {
      status: "open",
    };

    if (workplaceType) query.workplaceType = workplaceType;
    if (employmentType) query.employmentType = employmentType;

    const allJobs = await Job.find(query).sort({ updatedAt: -1, createdAt: -1 });
    
    const filteredJobs = [];
    for (const job of allJobs) {
      if (isDeadlinePassed(job.applicationDeadline)) continue;
      
      const company = await getCompanyById(job.companyId);
      const haystack = [
        job.title,
        job.description,
        job.location,
        ...(Array.isArray(job.requiredSkills) ? job.requiredSkills : []),
        company?.name || "",
      ]
        .join(" ")
        .toLowerCase();

      if (queryTerm && !haystack.includes(queryTerm)) continue;
      if (companyFilter && !(company?.name || "").toLowerCase().includes(companyFilter)) continue;
      if (locationFilter && !job.location.toLowerCase().includes(locationFilter)) continue;
      if (
        skillFilter &&
        !job.requiredSkills.some((skill) => skill.toLowerCase().includes(skillFilter))
      ) continue;
      
      filteredJobs.push(job);
    }

    const serializedJobs = await Promise.all(
      filteredJobs.map((job) => serializeJob(job))
    );

    res.json({ jobs: serializedJobs });
  });

  app.post("/api/companies/:companyId/jobs", requireAuth, requireRole(["recruiter", "admin"]), async (req, res) => {
    const actor = await User.findOne({ id: req.auth.userId });
    const company = await getCompanyById(sanitizeText(req.params.companyId, 80));
    if (!company) {
      res.status(404).json({ message: "Company not found." });
      return;
    }
    if (!canManageCompany(actor, company)) {
      res.status(403).json({ message: "You cannot manage this company." });
      return;
    }

    const title = sanitizeText(req.body.title, 120);
    const description = sanitizeMultilineText(req.body.description, 2000);
    const location = sanitizeText(req.body.location, 120);
    const requiredSkills = parseSkills(req.body.requiredSkills);
    const workplaceType = sanitizeText(req.body.workplaceType, 40).toLowerCase();
    const employmentType = sanitizeText(req.body.employmentType, 40).toLowerCase();
    const salaryMin = parseOptionalCurrency(req.body.salaryMin);
    const salaryMax = parseOptionalCurrency(req.body.salaryMax);
    const applicationDeadline = parseDateInput(req.body.applicationDeadline);

    if (!title || !description || !location || !applicationDeadline) {
      res.status(400).json({
        message: "title, description, location, and a valid applicationDeadline are required.",
      });
      return;
    }
    if (!JOB_WORKPLACE_TYPES.has(workplaceType)) {
      res.status(400).json({ message: "Invalid workplaceType." });
      return;
    }
    if (!JOB_EMPLOYMENT_TYPES.has(employmentType)) {
      res.status(400).json({ message: "Invalid employmentType." });
      return;
    }
    if (salaryMin !== null && salaryMax !== null && salaryMin > salaryMax) {
      res.status(400).json({ message: "salaryMin cannot exceed salaryMax." });
      return;
    }

    const timestamp = new Date().toISOString();
    const job = new Job({
      id: uuidv4(),
      companyId: company.id,
      title,
      description,
      requiredSkills,
      location,
      workplaceType,
      employmentType,
      salaryMin,
      salaryMax,
      applicationDeadline,
      status: "open",
      createdByUserId: actor.id,
      createdAt: timestamp,
      updatedAt: timestamp,
    });

    await job.save();
    company.updatedAt = timestamp;
    await company.save();
    await appendAuditLog({
      actorUserId: actor.id,
      action: "JOB_CREATED",
      targetUserId: actor.id,
      metadata: { companyId: company.id, jobId: job.id, title: job.title },
    });

    res.status(201).json({
      message: "Job posted successfully.",
      job: await serializeJob(job, actor),
    });
  });

  app.patch("/api/jobs/:jobId", requireAuth, requireRole(["recruiter", "admin"]), async (req, res) => {
    const actor = await User.findOne({ id: req.auth.userId });
    const job = await getJobById(sanitizeText(req.params.jobId, 80));
    const company = job ? await getCompanyById(job.companyId) : null;
    if (!job || !company) {
      res.status(404).json({ message: "Job not found." });
      return;
    }
    if (!canManageCompany(actor, company)) {
      res.status(403).json({ message: "You cannot manage this job." });
      return;
    }

    if (typeof req.body.title === "string") job.title = sanitizeText(req.body.title, 120);
    if (typeof req.body.description === "string") job.description = sanitizeMultilineText(req.body.description, 2000);
    if (typeof req.body.location === "string") job.location = sanitizeText(req.body.location, 120);
    if (req.body.requiredSkills !== undefined) job.requiredSkills = parseSkills(req.body.requiredSkills);
    if (typeof req.body.workplaceType === "string") {
      const nextWorkplaceType = sanitizeText(req.body.workplaceType, 40).toLowerCase();
      if (!JOB_WORKPLACE_TYPES.has(nextWorkplaceType)) {
        res.status(400).json({ message: "Invalid workplaceType." });
        return;
      }
      job.workplaceType = nextWorkplaceType;
    }
    if (typeof req.body.employmentType === "string") {
      const nextEmploymentType = sanitizeText(req.body.employmentType, 40).toLowerCase();
      if (!JOB_EMPLOYMENT_TYPES.has(nextEmploymentType)) {
        res.status(400).json({ message: "Invalid employmentType." });
        return;
      }
      job.employmentType = nextEmploymentType;
    }
    if (req.body.salaryMin !== undefined) job.salaryMin = parseOptionalCurrency(req.body.salaryMin);
    if (req.body.salaryMax !== undefined) job.salaryMax = parseOptionalCurrency(req.body.salaryMax);
    if (job.salaryMin !== null && job.salaryMax !== null && job.salaryMin > job.salaryMax) {
      res.status(400).json({ message: "salaryMin cannot exceed salaryMax." });
      return;
    }
    if (req.body.applicationDeadline !== undefined) {
      const applicationDeadline = parseDateInput(req.body.applicationDeadline);
      if (!applicationDeadline) {
        res.status(400).json({ message: "Provide a valid applicationDeadline." });
        return;
      }
      job.applicationDeadline = applicationDeadline;
    }
    if (typeof req.body.status === "string") {
      const status = sanitizeText(req.body.status, 40).toLowerCase();
      if (!JOB_STATUSES.has(status)) {
        res.status(400).json({ message: "Invalid status." });
        return;
      }
      job.status = status;
    }

    job.updatedAt = new Date().toISOString();
    company.updatedAt = job.updatedAt;
    await appendAuditLog({
      actorUserId: actor.id,
      action: "JOB_UPDATED",
      targetUserId: actor.id,
      metadata: { jobId: job.id, fields: Object.keys(req.body || {}) },
    });
    await job.save();
    await company.save();

    res.json({ message: "Job updated.", job: await serializeJob(job, actor) });
  });

  app.post("/api/jobs/:jobId/apply", requireAuth, requireRole(["user"]), async (req, res) => {
    const applicant = await User.findOne({ id: req.auth.userId });
    const job = await getJobById(sanitizeText(req.params.jobId, 80));
    const company = job ? await getCompanyById(job.companyId) : null;
    const coverNote = sanitizeMultilineText(req.body.coverNote, 1200);

    if (!applicant || !job || !company) {
      res.status(404).json({ message: "Job not found." });
      return;
    }
    if (job.status !== "open" || isDeadlinePassed(job.applicationDeadline)) {
      res.status(400).json({ message: "This job is no longer accepting applications." });
      return;
    }
    if (!applicant.resume) {
      res.status(400).json({
        message: "Upload your encrypted resume before applying to a job.",
      });
      return;
    }
    const alreadyApplied = await Application.exists({
      jobId: job.id,
      applicantUserId: applicant.id,
    });
    if (alreadyApplied) {
      res.status(409).json({ message: "You have already applied to this job." });
      return;
    }

    const timestamp = new Date().toISOString();
    const application = new Application({
      id: uuidv4(),
      jobId: job.id,
      companyId: company.id,
      applicantUserId: applicant.id,
      coverNote,
      status: "Applied",
      isShortlisted: false,
      recruiterNotes: [],
      statusHistory: [
        {
          id: uuidv4(),
          status: "Applied",
          actorUserId: applicant.id,
          note: "Application submitted.",
          createdAt: timestamp,
        },
      ],
      createdAt: timestamp,
      updatedAt: timestamp,
    });

    await application.save();
    await appendAuditLog({
      actorUserId: applicant.id,
      action: "JOB_APPLICATION_CREATED",
      targetUserId: applicant.id,
      metadata: { applicationId: application.id, companyId: company.id, jobId: job.id },
    });

    res.status(201).json({
      message: "Application submitted successfully.",
      application: await serializeApplication(application, applicant),
    });
  });

  app.get("/api/applications/my", requireAuth, async (req, res) => {
    const actor = await User.findOne({ id: req.auth.userId });
    if (!actor) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    const applications = await Application.find({ applicantUserId: actor.id }).sort({ updatedAt: -1, createdAt: -1 });
    const serializedApps = await Promise.all(
      applications.map((app) => serializeApplication(app, actor))
    );

    res.json({ applications: serializedApps });
  });

  app.get("/api/companies/:companyId/applications", requireAuth, requireRole(["recruiter", "admin"]), async (req, res) => {
    const actor = await User.findOne({ id: req.auth.userId });
    const company = await getCompanyById(sanitizeText(req.params.companyId, 80));
    if (!company) {
      res.status(404).json({ message: "Company not found." });
      return;
    }
    if (!canManageCompany(actor, company)) {
      res.status(403).json({ message: "You cannot manage this company." });
      return;
    }
    const applications = await Application.find({ companyId: company.id }).sort({ updatedAt: -1, createdAt: -1 });
    const serializedApps = await Promise.all(
      applications.map((app) => serializeApplication(app, actor))
    );

    res.json({ company: await serializeCompany(company, actor), applications: serializedApps });
  });

  app.get("/api/jobs/:jobId/applications", requireAuth, requireRole(["recruiter", "admin"]), async (req, res) => {
    const actor = await User.findOne({ id: req.auth.userId });
    const job = await getJobById(sanitizeText(req.params.jobId, 80));
    const company = job ? await getCompanyById(job.companyId) : null;
    if (!job || !company) {
      res.status(404).json({ message: "Job not found." });
      return;
    }
    if (!canManageCompany(actor, company)) {
      res.status(403).json({ message: "You cannot manage this job." });
      return;
    }
    const applications = await Application.find({ jobId: job.id });
    const serializedApps = await Promise.all(
      applications.map((app) => serializeApplication(app, actor))
    );

    res.json({ job: await serializeJob(job, actor), applications: serializedApps });
  });

  app.patch("/api/applications/:applicationId/review", requireAuth, requireRole(["recruiter", "admin"]), async (req, res) => {
    const actor = await User.findOne({ id: req.auth.userId });
    const application = await getApplicationById(sanitizeText(req.params.applicationId, 80));
    const job = application ? await getJobById(application.jobId) : null;
    const company = job ? await getCompanyById(job.companyId) : null;
    const status = typeof req.body.status === "string" ? sanitizeText(req.body.status, 40) : null;
    const note = sanitizeMultilineText(req.body.note, 800);

    if (!application || !job || !company) {
      res.status(404).json({ message: "Application not found." });
      return;
    }
    if (!canManageCompany(actor, company)) {
      res.status(403).json({ message: "You cannot review this application." });
      return;
    }
    if (status && !APPLICATION_STATUSES.has(status)) {
      res.status(400).json({ message: "Invalid application status." });
      return;
    }

    if (typeof req.body.isShortlisted === "boolean") {
      application.isShortlisted = req.body.isShortlisted;
    }
    if (status && status !== application.status) {
      application.status = status;
      application.statusHistory = Array.isArray(application.statusHistory)
        ? application.statusHistory
        : [];
      application.statusHistory.push({
        id: uuidv4(),
        status,
        actorUserId: actor.id,
        note: note || `Status changed to ${status}.`,
        createdAt: new Date().toISOString(),
      });
    }
    if (note) {
      application.recruiterNotes = Array.isArray(application.recruiterNotes)
        ? application.recruiterNotes
        : [];
      application.recruiterNotes.push({
        id: uuidv4(),
        authorUserId: actor.id,
        body: note,
        createdAt: new Date().toISOString(),
      });
    }

    application.updatedAt = new Date().toISOString();
    application.markModified("statusHistory");
    application.markModified("recruiterNotes");
    
    await appendAuditLog({
      actorUserId: actor.id,
      action: "APPLICATION_REVIEW_UPDATED",
      targetUserId: application.applicantUserId,
      metadata: {
        applicationId: application.id,
        companyId: company.id,
        jobId: job.id,
        status: application.status,
        isShortlisted: application.isShortlisted,
        noteAdded: Boolean(note),
      },
    });
    await application.save();

    res.json({
      message: "Application review updated.",
      application: await serializeApplication(application, actor),
    });
  });
}

module.exports = {
  registerOpportunityRoutes,
};
