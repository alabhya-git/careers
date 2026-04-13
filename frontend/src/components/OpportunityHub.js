import { useCallback, useEffect, useMemo, useState } from "react";

const defaultFilters = {
  q: "",
  company: "",
  location: "",
  skill: "",
  workplaceType: "",
  employmentType: "",
};

function formatDate(value) {
  if (!value) {
    return "-";
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
}

function buildQuery(filters) {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value) {
      params.set(key, value);
    }
  });
  const query = params.toString();
  return query ? `?${query}` : "";
}

function MatchInfo({ matchData }) {
  if (!matchData) return null;

  const { score, matchedKeywords } = matchData;
  let colorClass = "match-low";
  if (score >= 80) colorClass = "match-high";
  else if (score >= 50) colorClass = "match-medium";

  return (
    <div className="match-info">
      <div className={`match-score-badge ${colorClass}`}>
        <span className="match-icon">✨</span>
        <span>{score}% Match</span>
      </div>
      {matchedKeywords && matchedKeywords.length > 0 && (
        <div className="matched-keywords">
          {matchedKeywords.map((kw) => (
            <span key={kw} className="keyword-chip">
              {kw}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function OpportunityHub({ request, currentUser, onStatus, onError, clearFeedback }) {
  const [filters, setFilters] = useState(defaultFilters);
  const [jobs, setJobs] = useState([]);
  const [companies, setCompanies] = useState([]);
  const [applications, setApplications] = useState([]);
  const [coverNotes, setCoverNotes] = useState({});
  const [expandedJobId, setExpandedJobId] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const loadData = useCallback(
    async (activeFilters) => {
      setIsLoading(true);

      try {
        const [jobsResponse, companiesResponse, applicationsResponse] = await Promise.all([
          request(`/api/jobs${buildQuery(activeFilters)}`),
          request("/api/companies"),
          currentUser.role === "user"
            ? request("/api/applications/my", { auth: true })
            : Promise.resolve({ applications: [] }),
        ]);

        setJobs(jobsResponse.jobs || []);
        setCompanies(companiesResponse.companies || []);
        setApplications(applicationsResponse.applications || []);
      } catch (error) {
        onError(error.message);
      } finally {
        setIsLoading(false);
      }
    },
    [currentUser.role, onError, request]
  );

  useEffect(() => {
    loadData(defaultFilters);
  }, [loadData]);

  const appliedJobIds = useMemo(
    () => new Set(applications.map((application) => application.jobId)),
    [applications]
  );

  const handleSearchSubmit = async (event) => {
    event.preventDefault();
    clearFeedback();
    await loadData(filters);
  };

  const handleApply = async (jobId) => {
    clearFeedback();
    setIsLoading(true);

    try {
      const payload = await request(`/api/jobs/${jobId}/apply`, {
        method: "POST",
        auth: true,
        body: {
          coverNote: coverNotes[jobId] || "",
        },
      });

      onStatus(payload.message || "Application submitted successfully.");
      setCoverNotes((previous) => ({
        ...previous,
        [jobId]: "",
      }));
      setExpandedJobId("");
      await loadData(filters);
    } catch (error) {
      onError(error.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <section className="panel wide">
      <div className="section-heading">
        <div>
          <h2>Jobs and Companies</h2>
          <p className="muted-copy">
            Search by keyword, company, location, skill, remote preference, and role type.
          </p>
        </div>
      </div>

      <form className="search-grid" onSubmit={handleSearchSubmit}>
        <label>
          Keywords
          <input
            value={filters.q}
            onChange={(event) =>
              setFilters((previous) => ({ ...previous, q: event.target.value }))
            }
            placeholder="Frontend, security, React..."
          />
        </label>

        <label>
          Company
          <input
            value={filters.company}
            onChange={(event) =>
              setFilters((previous) => ({ ...previous, company: event.target.value }))
            }
          />
        </label>

        <label>
          Location
          <input
            value={filters.location}
            onChange={(event) =>
              setFilters((previous) => ({ ...previous, location: event.target.value }))
            }
          />
        </label>

        <label>
          Skill
          <input
            value={filters.skill}
            onChange={(event) =>
              setFilters((previous) => ({ ...previous, skill: event.target.value }))
            }
          />
        </label>

        <label>
          Workplace
          <select
            value={filters.workplaceType}
            onChange={(event) =>
              setFilters((previous) => ({
                ...previous,
                workplaceType: event.target.value,
              }))
            }
          >
            <option value="">Any</option>
            <option value="remote">Remote</option>
            <option value="hybrid">Hybrid</option>
            <option value="on-site">On-site</option>
          </select>
        </label>

        <label>
          Employment
          <select
            value={filters.employmentType}
            onChange={(event) =>
              setFilters((previous) => ({
                ...previous,
                employmentType: event.target.value,
              }))
            }
          >
            <option value="">Any</option>
            <option value="full-time">Full-time</option>
            <option value="part-time">Part-time</option>
            <option value="contract">Contract</option>
            <option value="internship">Internship</option>
          </select>
        </label>

        <button className="btn" type="submit" disabled={isLoading}>
          Search Jobs
        </button>
      </form>

      <div className="hub-grid">
        <div className="stack-panel">
          <div className="stack-panel-heading">
            <h3>Open Positions</h3>
            <span className="badge">{jobs.length} results</span>
          </div>

          <div className="card-stack">
            {jobs.map((job) => {
              const alreadyApplied = appliedJobIds.has(job.id);

              return (
                <article key={job.id} className="job-card">
                  <div className="job-card-header">
                    <div>
                      <h4>{job.title}</h4>
                      <p>{job.company?.name || "Unknown company"}</p>
                    </div>
                    <span className={`status-pill ${job.workplaceType || "neutral"}`}>
                      {job.workplaceType}
                    </span>
                  </div>

                  <MatchInfo matchData={job.matchData} />

                  <p className="muted-copy">
                    {job.location} • {job.employmentType} • Deadline {formatDate(job.applicationDeadline)}
                  </p>
                  <p>{job.description}</p>

                  <div className="chip-row">
                    {(job.requiredSkills || []).map((skill) => (
                      <span key={skill} className="chip">
                        {skill}
                      </span>
                    ))}
                  </div>

                  {currentUser.role === "user" ? (
                    <div className="inline-actions">
                      <button
                        type="button"
                        className="btn btn-ghost"
                        onClick={() =>
                          setExpandedJobId((previous) => (previous === job.id ? "" : job.id))
                        }
                        disabled={isLoading || alreadyApplied}
                      >
                        {alreadyApplied ? "Applied" : "Apply"}
                      </button>
                    </div>
                  ) : null}

                  {expandedJobId === job.id && !alreadyApplied ? (
                    <div className="inline-editor">
                      <label>
                        Cover Note
                        <textarea
                          rows="4"
                          value={coverNotes[job.id] || ""}
                          onChange={(event) =>
                            setCoverNotes((previous) => ({
                              ...previous,
                              [job.id]: event.target.value,
                            }))
                          }
                          placeholder="Short note to the hiring team"
                        />
                      </label>

                      <button
                        type="button"
                        className="btn"
                        onClick={() => handleApply(job.id)}
                        disabled={isLoading}
                      >
                        Submit Application
                      </button>
                    </div>
                  ) : null}
                </article>
              );
            })}

            {!jobs.length ? <p className="muted-copy">No jobs matched your filters.</p> : null}
          </div>
        </div>

        <div className="stack-panel">
          <div className="stack-panel-heading">
            <h3>Company Pages</h3>
            <span className="badge">{companies.length}</span>
          </div>

          <div className="card-stack">
            {companies.map((company) => (
              <article key={company.id} className="summary-card">
                <h4>{company.name}</h4>
                <p className="muted-copy">
                  {company.location} • {company.counts?.openJobs || 0} open jobs
                </p>
                <p>{company.description}</p>
                <a
                  className="text-link inline"
                  href={company.website}
                  target="_blank"
                  rel="noreferrer"
                >
                  Visit website
                </a>
              </article>
            ))}
          </div>
        </div>
      </div>

      {currentUser.role === "user" ? (
        <div className="stack-panel">
          <div className="stack-panel-heading">
            <h3>My Applications</h3>
            <span className="badge">{applications.length}</span>
          </div>

          <div className="card-stack">
            {applications.map((application) => (
              <article key={application.id} className="summary-card">
                <div className="job-card-header">
                  <div>
                    <h4>{application.job?.title}</h4>
                    <p>{application.company?.name}</p>
                  </div>
                  <span className={`status-pill status-${String(application.status).toLowerCase()}`}>
                    {application.status}
                  </span>
                </div>
                <p className="muted-copy">
                  Applied {formatDate(application.createdAt)}
                  {application.isShortlisted ? " • Shortlisted" : ""}
                </p>
                <p>{application.coverNote || "No cover note shared."}</p>

                <div className="timeline-list">
                  {(application.statusHistory || []).map((entry) => (
                    <div key={entry.id} className="timeline-entry">
                      <strong>{entry.status}</strong>
                      <span>{formatDate(entry.createdAt)}</span>
                      <p>{entry.note}</p>
                    </div>
                  ))}
                </div>
              </article>
            ))}

            {!applications.length ? (
              <p className="muted-copy">You have not applied to any jobs yet.</p>
            ) : null}
          </div>
        </div>
      ) : null}
    </section>
  );
}

export default OpportunityHub;
