import { useCallback, useEffect, useMemo, useState } from "react";

const defaultCompanyForm = {
  name: "",
  description: "",
  location: "",
  website: "",
};

const defaultJobForm = {
  title: "",
  description: "",
  requiredSkills: "",
  location: "",
  workplaceType: "remote",
  employmentType: "full-time",
  salaryMin: "",
  salaryMax: "",
  applicationDeadline: "",
  status: "open",
};

function formatDate(value) {
  if (!value) {
    return "";
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString().slice(0, 16);
}

function formatHumanDate(value) {
  if (!value) {
    return "-";
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
}

function buildCompanyForm(company) {
  return {
    name: company?.name || "",
    description: company?.description || "",
    location: company?.location || "",
    website: company?.website || "",
  };
}

function buildJobForm(job) {
  return {
    title: job?.title || "",
    description: job?.description || "",
    requiredSkills: Array.isArray(job?.requiredSkills) ? job.requiredSkills.join(", ") : "",
    location: job?.location || "",
    workplaceType: job?.workplaceType || "remote",
    employmentType: job?.employmentType || "full-time",
    salaryMin: job?.salaryMin ?? "",
    salaryMax: job?.salaryMax ?? "",
    applicationDeadline: formatDate(job?.applicationDeadline),
    status: job?.status || "open",
  };
}

function HiringHub({ request, onStatus, onError, clearFeedback }) {
  const [companies, setCompanies] = useState([]);
  const [applications, setApplications] = useState([]);
  const [selectedCompanyId, setSelectedCompanyId] = useState("");
  const [editingCompanyId, setEditingCompanyId] = useState("");
  const [editingJobId, setEditingJobId] = useState("");
  const [companyForm, setCompanyForm] = useState(defaultCompanyForm);
  const [jobForm, setJobForm] = useState(defaultJobForm);
  const [applicationDrafts, setApplicationDrafts] = useState({});
  const [isLoading, setIsLoading] = useState(false);

  const loadCompanies = useCallback(async () => {
    const payload = await request("/api/companies/mine", { auth: true });
    setCompanies(payload.companies || []);
  }, [request]);

  const loadApplications = useCallback(
    async (companyId) => {
      if (!companyId) {
        setApplications([]);
        return;
      }

      const payload = await request(`/api/companies/${companyId}/applications`, {
        auth: true,
      });
      const nextApplications = payload.applications || [];
      setApplications(nextApplications);
      setApplicationDrafts(
        nextApplications.reduce((drafts, application) => {
          drafts[application.id] = {
            status: application.status,
            isShortlisted: Boolean(application.isShortlisted),
            note: "",
          };
          return drafts;
        }, {})
      );
    },
    [request]
  );

  useEffect(() => {
    setIsLoading(true);
    loadCompanies()
      .catch((error) => onError(error.message))
      .finally(() => setIsLoading(false));
  }, [loadCompanies, onError]);

  useEffect(() => {
    if (!selectedCompanyId) {
      return;
    }

    setIsLoading(true);
    loadApplications(selectedCompanyId)
      .catch((error) => onError(error.message))
      .finally(() => setIsLoading(false));
  }, [loadApplications, onError, selectedCompanyId]);

  const selectedCompany = useMemo(
    () => companies.find((company) => company.id === selectedCompanyId) || null,
    [companies, selectedCompanyId]
  );

  const handleCompanySubmit = async (event) => {
    event.preventDefault();
    clearFeedback();
    setIsLoading(true);

    try {
      const endpoint = editingCompanyId
        ? `/api/companies/${editingCompanyId}`
        : "/api/companies";
      const method = editingCompanyId ? "PATCH" : "POST";
      const payload = await request(endpoint, {
        method,
        auth: true,
        body: companyForm,
      });

      onStatus(payload.message || "Company saved.");
      await loadCompanies();
      if (!editingCompanyId && payload.company?.id) {
        setSelectedCompanyId(payload.company.id);
        setEditingCompanyId(payload.company.id);
      }
    } catch (error) {
      onError(error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleJobSubmit = async (event) => {
    event.preventDefault();
    clearFeedback();

    if (!selectedCompanyId) {
      onError("Select a company before creating or editing a job.");
      return;
    }

    setIsLoading(true);

    try {
      const endpoint = editingJobId
        ? `/api/jobs/${editingJobId}`
        : `/api/companies/${selectedCompanyId}/jobs`;
      const method = editingJobId ? "PATCH" : "POST";
      const payload = await request(endpoint, {
        method,
        auth: true,
        body: jobForm,
      });

      onStatus(payload.message || "Job saved.");
      setEditingJobId("");
      setJobForm(defaultJobForm);
      await loadCompanies();
      await loadApplications(selectedCompanyId);
    } catch (error) {
      onError(error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleApplicationUpdate = async (applicationId) => {
    clearFeedback();
    setIsLoading(true);

    try {
      const payload = await request(`/api/applications/${applicationId}/review`, {
        method: "PATCH",
        auth: true,
        body: applicationDrafts[applicationId],
      });

      onStatus(payload.message || "Application review updated.");
      await loadApplications(selectedCompanyId);
      await loadCompanies();
    } catch (error) {
      onError(error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const selectCompanyForEditing = (company) => {
    setSelectedCompanyId(company.id);
    setEditingCompanyId(company.id);
    setCompanyForm(buildCompanyForm(company));
    setEditingJobId("");
    setJobForm(defaultJobForm);
  };

  return (
    <section className="panel wide">
      <div className="section-heading">
        <div>
          <h2>Recruiter Workspace</h2>
          <p className="muted-copy">
            Manage company pages, publish job postings, and move candidates through the pipeline.
          </p>
        </div>
        <button
          type="button"
          className="btn btn-ghost"
          onClick={() => {
            setEditingCompanyId("");
            setCompanyForm(defaultCompanyForm);
          }}
        >
          New Company
        </button>
      </div>

      <div className="hub-grid">
        <div className="stack-panel">
          <div className="stack-panel-heading">
            <h3>Company Manager</h3>
            <span className="badge">{companies.length}</span>
          </div>

          <form onSubmit={handleCompanySubmit}>
            <label>
              Company Name
              <input
                value={companyForm.name}
                onChange={(event) =>
                  setCompanyForm((previous) => ({ ...previous, name: event.target.value }))
                }
                required
              />
            </label>

            <label>
              Description
              <textarea
                rows="4"
                value={companyForm.description}
                onChange={(event) =>
                  setCompanyForm((previous) => ({
                    ...previous,
                    description: event.target.value,
                  }))
                }
                required
              />
            </label>

            <div className="grid-two">
              <label>
                Location
                <input
                  value={companyForm.location}
                  onChange={(event) =>
                    setCompanyForm((previous) => ({
                      ...previous,
                      location: event.target.value,
                    }))
                  }
                  required
                />
              </label>

              <label>
                Website
                <input
                  value={companyForm.website}
                  onChange={(event) =>
                    setCompanyForm((previous) => ({
                      ...previous,
                      website: event.target.value,
                    }))
                  }
                  required
                />
              </label>
            </div>

            <button className="btn" type="submit" disabled={isLoading}>
              {editingCompanyId ? "Save Company" : "Create Company"}
            </button>
          </form>

          <div className="card-stack">
            {companies.map((company) => (
              <article key={company.id} className="summary-card">
                <div className="job-card-header">
                  <div>
                    <h4>{company.name}</h4>
                    <p>{company.location}</p>
                  </div>
                  <span className="badge">{company.counts?.openJobs || 0} open</span>
                </div>

                <p>{company.description}</p>
                <div className="inline-actions">
                  <button
                    type="button"
                    className="btn btn-ghost"
                    onClick={() => selectCompanyForEditing(company)}
                  >
                    Manage
                  </button>
                </div>
              </article>
            ))}
          </div>
        </div>

        <div className="stack-panel">
          <div className="stack-panel-heading">
            <h3>Jobs and Applicants</h3>
            <span className="badge">{selectedCompany?.jobs?.length || 0} jobs</span>
          </div>

          {selectedCompany ? (
            <>
              <form onSubmit={handleJobSubmit}>
                <div className="grid-two">
                  <label>
                    Job Title
                    <input
                      value={jobForm.title}
                      onChange={(event) =>
                        setJobForm((previous) => ({ ...previous, title: event.target.value }))
                      }
                      required
                    />
                  </label>

                  <label>
                    Location
                    <input
                      value={jobForm.location}
                      onChange={(event) =>
                        setJobForm((previous) => ({
                          ...previous,
                          location: event.target.value,
                        }))
                      }
                      required
                    />
                  </label>
                </div>

                <label>
                  Description
                  <textarea
                    rows="4"
                    value={jobForm.description}
                    onChange={(event) =>
                      setJobForm((previous) => ({
                        ...previous,
                        description: event.target.value,
                      }))
                    }
                    required
                  />
                </label>

                <label>
                  Required Skills
                  <input
                    value={jobForm.requiredSkills}
                    onChange={(event) =>
                      setJobForm((previous) => ({
                        ...previous,
                        requiredSkills: event.target.value,
                      }))
                    }
                    placeholder="React, Node.js, AWS"
                  />
                </label>

                <div className="grid-two">
                  <label>
                    Workplace
                    <select
                      value={jobForm.workplaceType}
                      onChange={(event) =>
                        setJobForm((previous) => ({
                          ...previous,
                          workplaceType: event.target.value,
                        }))
                      }
                    >
                      <option value="remote">Remote</option>
                      <option value="hybrid">Hybrid</option>
                      <option value="on-site">On-site</option>
                    </select>
                  </label>

                  <label>
                    Employment
                    <select
                      value={jobForm.employmentType}
                      onChange={(event) =>
                        setJobForm((previous) => ({
                          ...previous,
                          employmentType: event.target.value,
                        }))
                      }
                    >
                      <option value="full-time">Full-time</option>
                      <option value="part-time">Part-time</option>
                      <option value="contract">Contract</option>
                      <option value="internship">Internship</option>
                    </select>
                  </label>

                  <label>
                    Salary Min
                    <input
                      type="number"
                      value={jobForm.salaryMin}
                      onChange={(event) =>
                        setJobForm((previous) => ({
                          ...previous,
                          salaryMin: event.target.value,
                        }))
                      }
                    />
                  </label>

                  <label>
                    Salary Max
                    <input
                      type="number"
                      value={jobForm.salaryMax}
                      onChange={(event) =>
                        setJobForm((previous) => ({
                          ...previous,
                          salaryMax: event.target.value,
                        }))
                      }
                    />
                  </label>

                  <label>
                    Deadline
                    <input
                      type="datetime-local"
                      value={jobForm.applicationDeadline}
                      onChange={(event) =>
                        setJobForm((previous) => ({
                          ...previous,
                          applicationDeadline: event.target.value,
                        }))
                      }
                      required
                    />
                  </label>

                  <label>
                    Status
                    <select
                      value={jobForm.status}
                      onChange={(event) =>
                        setJobForm((previous) => ({
                          ...previous,
                          status: event.target.value,
                        }))
                      }
                    >
                      <option value="open">Open</option>
                      <option value="closed">Closed</option>
                    </select>
                  </label>
                </div>

                <div className="inline-actions">
                  <button className="btn" type="submit" disabled={isLoading}>
                    {editingJobId ? "Save Job" : "Post Job"}
                  </button>
                  {editingJobId ? (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => {
                        setEditingJobId("");
                        setJobForm(defaultJobForm);
                      }}
                    >
                      Cancel Job Edit
                    </button>
                  ) : null}
                </div>
              </form>

              <div className="card-stack">
                {(selectedCompany.jobs || []).map((job) => (
                  <article key={job.id} className="summary-card">
                    <div className="job-card-header">
                      <div>
                        <h4>{job.title}</h4>
                        <p>
                          {job.location} • {job.employmentType}
                        </p>
                      </div>
                      <span className={`status-pill status-${job.status}`}>{job.status}</span>
                    </div>
                    <p className="muted-copy">
                      {job.applicantCount || 0} applicants • Deadline {formatHumanDate(job.applicationDeadline)}
                    </p>
                    <div className="inline-actions">
                      <button
                        type="button"
                        className="btn btn-ghost"
                        onClick={() => {
                          setEditingJobId(job.id);
                          setJobForm(buildJobForm(job));
                        }}
                      >
                        Edit Job
                      </button>
                    </div>
                  </article>
                ))}
              </div>

              <div className="card-stack">
                {applications.map((application) => (
                  <article key={application.id} className="summary-card">
                    <div className="job-card-header">
                      <div>
                        <h4>
                          {application.applicant?.profile?.name || application.applicant?.email}
                        </h4>
                        <p>
                          {application.job?.title} • {application.company?.name}
                        </p>
                      </div>
                      <span className={`status-pill status-${String(application.status).toLowerCase()}`}>
                        {application.status}
                      </span>
                    </div>

                    <p>{application.coverNote || "No cover note shared."}</p>
                    <p className="muted-copy">
                      Applied {formatHumanDate(application.createdAt)}
                      {application.applicantResume?.originalName
                        ? ` • Resume ${application.applicantResume.originalName}`
                        : ""}
                    </p>

                    <div className="grid-two">
                      <label>
                        Status
                        <select
                          value={applicationDrafts[application.id]?.status || application.status}
                          onChange={(event) =>
                            setApplicationDrafts((previous) => ({
                              ...previous,
                              [application.id]: {
                                ...previous[application.id],
                                status: event.target.value,
                              },
                            }))
                          }
                        >
                          <option value="Applied">Applied</option>
                          <option value="Reviewed">Reviewed</option>
                          <option value="Interviewed">Interviewed</option>
                          <option value="Rejected">Rejected</option>
                          <option value="Offer">Offer</option>
                        </select>
                      </label>

                      <label className="checkbox-row">
                        <input
                          type="checkbox"
                          checked={Boolean(applicationDrafts[application.id]?.isShortlisted)}
                          onChange={(event) =>
                            setApplicationDrafts((previous) => ({
                              ...previous,
                              [application.id]: {
                                ...previous[application.id],
                                isShortlisted: event.target.checked,
                              },
                            }))
                          }
                        />
                        Shortlisted
                      </label>
                    </div>

                    <label>
                      Recruiter Note
                      <textarea
                        rows="3"
                        value={applicationDrafts[application.id]?.note || ""}
                        onChange={(event) =>
                          setApplicationDrafts((previous) => ({
                            ...previous,
                            [application.id]: {
                              ...previous[application.id],
                              note: event.target.value,
                            },
                          }))
                        }
                      />
                    </label>

                    <button
                      type="button"
                      className="btn"
                      onClick={() => handleApplicationUpdate(application.id)}
                      disabled={isLoading}
                    >
                      Save Review
                    </button>
                  </article>
                ))}

                {!applications.length ? (
                  <p className="muted-copy">No applications yet for this company.</p>
                ) : null}
              </div>
            </>
          ) : (
            <p className="muted-copy">
              Choose a company from the left column to manage jobs and candidate applications.
            </p>
          )}
        </div>
      </div>
    </section>
  );
}

export default HiringHub;
