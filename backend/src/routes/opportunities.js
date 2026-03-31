const { v4: uuidv4 } = require("uuid");
const { appendAuditLog } = require("../audit");
const { readDb, writeDb } = require("../store");
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
  app.get("/api/companies", (req, res) => {
    const db = readDb();
    const query = sanitizeText(req.query.q || "", 120).toLowerCase();

    const companies = db.companies
      .filter((company) => {
        if (!query) {
          return true;
        }

        const haystack = [
          company.name,
          company.description,
          company.location,
          company.website,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();

        return haystack.includes(query);
      })
      .sort((left, right) => {
        const rightDate = new Date(right.updatedAt || right.createdAt || 0).getTime();
        const leftDate = new Date(left.updatedAt || left.createdAt || 0).getTime();
        return rightDate - leftDate;
      })
      .map((company) => serializeCompany(db, company));

    res.json({ companies });
  });

  app.get("/api/companies/mine", requireAuth, requireRole(["recruiter", "admin"]), (req, res) => {
    const db = readDb();
    const actor = db.users.find((item) => item.id === req.auth.userId);
    const managedCompanyIds = new Set(getManagedCompanyIds(db, actor));
    const companies = db.companies
      .filter((company) => managedCompanyIds.has(company.id))
      .sort((left, right) => {
        const rightDate = new Date(right.updatedAt || right.createdAt || 0).getTime();
        const leftDate = new Date(left.updatedAt || left.createdAt || 0).getTime();
        return rightDate - leftDate;
      })
      .map((company) => ({
        ...serializeCompany(db, company, actor),
        jobs: db.jobs
          .filter((job) => job.companyId === company.id)
          .sort((left, right) => {
            const rightDate = new Date(right.updatedAt || right.createdAt || 0).getTime();
            const leftDate = new Date(left.updatedAt || left.createdAt || 0).getTime();
            return rightDate - leftDate;
          })
          .map((job) => serializeJob(db, job, actor)),
      }));

    res.json({ companies });
  });

  app.post("/api/companies", requireAuth, requireRole(["recruiter", "admin"]), (req, res) => {
    const name = sanitizeText(req.body.name, 120);
    const description = sanitizeMultilineText(req.body.description, 1200);
    const location = sanitizeText(req.body.location, 120);
    const website = sanitizeUrl(req.body.website);
    const adminUserIds = Array.from(
      new Set([req.auth.userId, ...parseIdList(req.body.adminUserIds)])
    );

    if (!name || !description || !location || !website) {
      res.status(400).json({
        message: "name, description, location, and a valid website are required.",
      });
      return;
    }

    const db = readDb();
    const invalidAdmin = adminUserIds.find((userId) => {
      const candidate = db.users.find((user) => user.id === userId);
      return !candidate || !["recruiter", "admin"].includes(candidate.role);
    });
    if (invalidAdmin) {
      res.status(400).json({
        message: "All company admins must be recruiter or admin accounts.",
      });
      return;
    }

    const timestamp = new Date().toISOString();
    const company = {
      id: uuidv4(),
      slug: createUniqueCompanySlug(db, name),
      name,
      description,
      location,
      website,
      createdByUserId: req.auth.userId,
      adminUserIds,
      createdAt: timestamp,
      updatedAt: timestamp,
    };

    db.companies.push(company);
    appendAuditLog(db, {
      actorUserId: req.auth.userId,
      action: "COMPANY_CREATED",
      targetUserId: req.auth.userId,
      metadata: { companyId: company.id, companyName: company.name },
    });
    writeDb(db);

    res.status(201).json({
      message: "Company page created.",
      company: serializeCompany(db, company, db.users.find((user) => user.id === req.auth.userId)),
    });
  });

  app.patch("/api/companies/:companyId", requireAuth, requireRole(["recruiter", "admin"]), (req, res) => {
    const db = readDb();
    const actor = db.users.find((item) => item.id === req.auth.userId);
    const company = getCompanyById(db, sanitizeText(req.params.companyId, 80));
    if (!company) {
      res.status(404).json({ message: "Company not found." });
      return;
    }
    if (!canManageCompany(db, actor, company)) {
      res.status(403).json({ message: "You cannot manage this company." });
      return;
    }

    if (typeof req.body.name === "string") {
      company.name = sanitizeText(req.body.name, 120);
      company.slug = createUniqueCompanySlug(db, company.name, company.id);
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
      const invalidAdmin = nextAdminUserIds.find((userId) => {
        const candidate = db.users.find((user) => user.id === userId);
        return !candidate || !["recruiter", "admin"].includes(candidate.role);
      });
      if (invalidAdmin) {
        res.status(400).json({
          message: "All company admins must be recruiter or admin accounts.",
        });
        return;
      }
      company.adminUserIds = nextAdminUserIds;
    }

    company.updatedAt = new Date().toISOString();
    appendAuditLog(db, {
      actorUserId: actor.id,
      action: "COMPANY_UPDATED",
      targetUserId: actor.id,
      metadata: { companyId: company.id, fields: Object.keys(req.body || {}) },
    });
    writeDb(db);

    res.json({
      message: "Company updated.",
      company: serializeCompany(db, company, actor),
    });
  });

  app.get("/api/companies/:companyId", (req, res) => {
    const db = readDb();
    const company = getCompanyById(db, sanitizeText(req.params.companyId, 80));
    if (!company) {
      res.status(404).json({ message: "Company not found." });
      return;
    }

    res.json({
      company: serializeCompany(db, company),
      jobs: db.jobs
        .filter(
          (job) =>
            job.companyId === company.id &&
            job.status === "open" &&
            !isDeadlinePassed(job.applicationDeadline)
        )
        .map((job) => serializeJob(db, job)),
    });
  });

  app.get("/api/jobs", (req, res) => {
    const db = readDb();
    const query = sanitizeText(req.query.q || "", 120).toLowerCase();
    const companyFilter = sanitizeText(req.query.company || "", 120).toLowerCase();
    const locationFilter = sanitizeText(req.query.location || "", 120).toLowerCase();
    const skillFilter = sanitizeText(req.query.skill || "", 40).toLowerCase();
    const workplaceType = sanitizeText(req.query.workplaceType || "", 40).toLowerCase();
    const employmentType = sanitizeText(req.query.employmentType || "", 40).toLowerCase();

    const jobs = db.jobs
      .filter((job) => job.status === "open" && !isDeadlinePassed(job.applicationDeadline))
      .filter((job) => {
        const company = getCompanyById(db, job.companyId);
        const haystack = [
          job.title,
          job.description,
          job.location,
          ...(Array.isArray(job.requiredSkills) ? job.requiredSkills : []),
          company?.name || "",
        ]
          .join(" ")
          .toLowerCase();
        if (query && !haystack.includes(query)) return false;
        if (companyFilter && !(company?.name || "").toLowerCase().includes(companyFilter)) return false;
        if (locationFilter && !job.location.toLowerCase().includes(locationFilter)) return false;
        if (
          skillFilter &&
          !job.requiredSkills.some((skill) => skill.toLowerCase().includes(skillFilter))
        ) return false;
        if (workplaceType && job.workplaceType !== workplaceType) return false;
        if (employmentType && job.employmentType !== employmentType) return false;
        return true;
      })
      .sort((left, right) => {
        const rightDate = new Date(right.updatedAt || right.createdAt || 0).getTime();
        const leftDate = new Date(left.updatedAt || left.createdAt || 0).getTime();
        return rightDate - leftDate;
      })
      .map((job) => serializeJob(db, job));

    res.json({ jobs });
  });

  app.post("/api/companies/:companyId/jobs", requireAuth, requireRole(["recruiter", "admin"]), (req, res) => {
    const db = readDb();
    const actor = db.users.find((item) => item.id === req.auth.userId);
    const company = getCompanyById(db, sanitizeText(req.params.companyId, 80));
    if (!company) {
      res.status(404).json({ message: "Company not found." });
      return;
    }
    if (!canManageCompany(db, actor, company)) {
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
    const job = {
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
    };

    db.jobs.push(job);
    company.updatedAt = timestamp;
    appendAuditLog(db, {
      actorUserId: actor.id,
      action: "JOB_CREATED",
      targetUserId: actor.id,
      metadata: { companyId: company.id, jobId: job.id, title: job.title },
    });
    writeDb(db);

    res.status(201).json({
      message: "Job posted successfully.",
      job: serializeJob(db, job, actor),
    });
  });

  app.patch("/api/jobs/:jobId", requireAuth, requireRole(["recruiter", "admin"]), (req, res) => {
    const db = readDb();
    const actor = db.users.find((item) => item.id === req.auth.userId);
    const job = getJobById(db, sanitizeText(req.params.jobId, 80));
    const company = job ? getCompanyById(db, job.companyId) : null;
    if (!job || !company) {
      res.status(404).json({ message: "Job not found." });
      return;
    }
    if (!canManageCompany(db, actor, company)) {
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
    appendAuditLog(db, {
      actorUserId: actor.id,
      action: "JOB_UPDATED",
      targetUserId: actor.id,
      metadata: { jobId: job.id, fields: Object.keys(req.body || {}) },
    });
    writeDb(db);

    res.json({ message: "Job updated.", job: serializeJob(db, job, actor) });
  });

  app.post("/api/jobs/:jobId/apply", requireAuth, requireRole(["user"]), (req, res) => {
    const db = readDb();
    const applicant = db.users.find((item) => item.id === req.auth.userId);
    const job = getJobById(db, sanitizeText(req.params.jobId, 80));
    const company = job ? getCompanyById(db, job.companyId) : null;
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
    if (
      db.applications.some(
        (application) =>
          application.jobId === job.id && application.applicantUserId === applicant.id
      )
    ) {
      res.status(409).json({ message: "You have already applied to this job." });
      return;
    }

    const timestamp = new Date().toISOString();
    const application = {
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
    };

    db.applications.push(application);
    appendAuditLog(db, {
      actorUserId: applicant.id,
      action: "JOB_APPLICATION_CREATED",
      targetUserId: applicant.id,
      metadata: { applicationId: application.id, companyId: company.id, jobId: job.id },
    });
    writeDb(db);

    res.status(201).json({
      message: "Application submitted successfully.",
      application: serializeApplication(db, application, applicant),
    });
  });

  app.get("/api/applications/my", requireAuth, (req, res) => {
    const db = readDb();
    const actor = db.users.find((item) => item.id === req.auth.userId);
    if (!actor) {
      res.status(404).json({ message: "User not found." });
      return;
    }

    const applications = db.applications
      .filter((application) => application.applicantUserId === actor.id)
      .sort((left, right) => {
        const rightDate = new Date(right.updatedAt || right.createdAt || 0).getTime();
        const leftDate = new Date(left.updatedAt || left.createdAt || 0).getTime();
        return rightDate - leftDate;
      })
      .map((application) => serializeApplication(db, application, actor));

    res.json({ applications });
  });

  app.get("/api/companies/:companyId/applications", requireAuth, requireRole(["recruiter", "admin"]), (req, res) => {
    const db = readDb();
    const actor = db.users.find((item) => item.id === req.auth.userId);
    const company = getCompanyById(db, sanitizeText(req.params.companyId, 80));
    if (!company) {
      res.status(404).json({ message: "Company not found." });
      return;
    }
    if (!canManageCompany(db, actor, company)) {
      res.status(403).json({ message: "You cannot manage this company." });
      return;
    }
    const applications = db.applications
      .filter((application) => application.companyId === company.id)
      .sort((left, right) => {
        const rightDate = new Date(right.updatedAt || right.createdAt || 0).getTime();
        const leftDate = new Date(left.updatedAt || left.createdAt || 0).getTime();
        return rightDate - leftDate;
      })
      .map((application) => serializeApplication(db, application, actor));

    res.json({ company: serializeCompany(db, company, actor), applications });
  });

  app.get("/api/jobs/:jobId/applications", requireAuth, requireRole(["recruiter", "admin"]), (req, res) => {
    const db = readDb();
    const actor = db.users.find((item) => item.id === req.auth.userId);
    const job = getJobById(db, sanitizeText(req.params.jobId, 80));
    const company = job ? getCompanyById(db, job.companyId) : null;
    if (!job || !company) {
      res.status(404).json({ message: "Job not found." });
      return;
    }
    if (!canManageCompany(db, actor, company)) {
      res.status(403).json({ message: "You cannot manage this job." });
      return;
    }
    const applications = db.applications
      .filter((application) => application.jobId === job.id)
      .map((application) => serializeApplication(db, application, actor));

    res.json({ job: serializeJob(db, job, actor), applications });
  });

  app.patch("/api/applications/:applicationId/review", requireAuth, requireRole(["recruiter", "admin"]), (req, res) => {
    const db = readDb();
    const actor = db.users.find((item) => item.id === req.auth.userId);
    const application = getApplicationById(db, sanitizeText(req.params.applicationId, 80));
    const job = application ? getJobById(db, application.jobId) : null;
    const company = job ? getCompanyById(db, job.companyId) : null;
    const status = typeof req.body.status === "string" ? sanitizeText(req.body.status, 40) : null;
    const note = sanitizeMultilineText(req.body.note, 800);

    if (!application || !job || !company) {
      res.status(404).json({ message: "Application not found." });
      return;
    }
    if (!canManageCompany(db, actor, company)) {
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
    appendAuditLog(db, {
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
    writeDb(db);

    res.json({
      message: "Application review updated.",
      application: serializeApplication(db, application, actor),
    });
  });
}

module.exports = {
  registerOpportunityRoutes,
};
