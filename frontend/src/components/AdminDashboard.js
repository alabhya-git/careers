import { useCallback, useEffect, useMemo, useState } from "react";

function formatDate(value) {
  if (!value) {
    return "-";
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString();
}

function prettyRole(role) {
  if (role === "admin") {
    return "Admin";
  }

  if (role === "recruiter") {
    return "Recruiter";
  }

  return "User";
}

function AdminDashboard({ request, currentUser, onStatus, onError, clearFeedback }) {
  const [overview, setOverview] = useState(null);
  const [users, setUsers] = useState([]);
  const [logs, setLogs] = useState([]);
  const [logSearch, setLogSearch] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const loadDashboard = useCallback(async () => {
    const [overviewResult, usersResult, logsResult] = await Promise.all([
      request("/api/admin/overview", { auth: true }),
      request("/api/admin/users", { auth: true }),
      request(`/api/admin/audit-logs?limit=25&search=${encodeURIComponent(logSearch)}`, {
        auth: true,
      }),
    ]);

    setOverview(overviewResult);
    setUsers(usersResult.users || []);
    setLogs(logsResult.logs || []);
  }, [logSearch, request]);

  useEffect(() => {
    setIsLoading(true);
    loadDashboard()
      .catch((error) => onError(error.message))
      .finally(() => setIsLoading(false));
  }, [loadDashboard, onError]);

  const totals = useMemo(() => overview?.totals || {}, [overview]);

  const toggleUserSuspension = async (user) => {
    clearFeedback();
    setIsLoading(true);

    try {
      const payload = await request(`/api/admin/users/${user.id}/suspension`, {
        method: "PATCH",
        auth: true,
        body: {
          isSuspended: !user.isSuspended,
          reason: user.isSuspended
            ? "Reactivated from admin dashboard"
            : "Suspended from admin dashboard",
        },
      });

      onStatus(payload.message || "User status updated.");
      await loadDashboard();
    } catch (error) {
      onError(error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const deleteUser = async (userId) => {
    clearFeedback();
    setIsLoading(true);

    try {
      const payload = await request(`/api/admin/users/${userId}`, {
        method: "DELETE",
        auth: true,
      });

      onStatus(payload.message || "User deleted.");
      await loadDashboard();
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
          <h2>Admin Dashboard</h2>
          <p className="muted-copy">
            Platform totals, moderation actions, and tamper-evident audit activity.
          </p>
        </div>
      </div>

      <div className="kpi-grid kpi-grid-wide">
        <div className="kpi">
          <span>Total Users</span>
          <strong>{totals.totalUsers || 0}</strong>
        </div>
        <div className="kpi">
          <span>TOTP Enabled</span>
          <strong>{totals.verifiedUsers || 0}</strong>
        </div>
        <div className="kpi">
          <span>Recruiters</span>
          <strong>{totals.recruiterUsers || 0}</strong>
        </div>
        <div className="kpi">
          <span>Companies</span>
          <strong>{totals.totalCompanies || 0}</strong>
        </div>
        <div className="kpi">
          <span>Jobs</span>
          <strong>{totals.totalJobs || 0}</strong>
        </div>
        <div className="kpi">
          <span>Applications</span>
          <strong>{totals.totalApplications || 0}</strong>
        </div>
        <div className="kpi">
          <span>Conversations</span>
          <strong>{totals.totalConversations || 0}</strong>
        </div>
        <div className="kpi">
          <span>Messages</span>
          <strong>{totals.totalMessages || 0}</strong>
        </div>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id}>
                <td>{user.profile?.name || "-"}</td>
                <td>{user.email}</td>
                <td>{prettyRole(user.role)}</td>
                <td>{user.isSuspended ? "Suspended" : "Active"}</td>
                <td>{formatDate(user.createdAt)}</td>
                <td>
                  <div className="action-buttons">
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => toggleUserSuspension(user)}
                      disabled={isLoading || user.id === currentUser.id}
                    >
                      {user.isSuspended ? "Activate" : "Suspend"}
                    </button>
                    <button
                      type="button"
                      className="btn btn-danger"
                      onClick={() => deleteUser(user.id)}
                      disabled={isLoading || user.id === currentUser.id}
                    >
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="stack-panel">
        <div className="stack-panel-heading">
          <h3>Recent Audit Logs</h3>
          <span className="badge">{logs.length}</span>
        </div>

        <label>
          Filter Logs
          <input
            value={logSearch}
            onChange={(event) => setLogSearch(event.target.value)}
            placeholder="Search by action, user, or metadata"
          />
        </label>

        <button className="btn btn-ghost" type="button" onClick={loadDashboard} disabled={isLoading}>
          Refresh Logs
        </button>

        <div className="card-stack">
          {logs.map((log) => (
            <article key={log.id} className="summary-card">
              <div className="job-card-header">
                <div>
                  <h4>{log.action}</h4>
                  <p>{formatDate(log.timestamp)}</p>
                </div>
                <span className="badge">{log.actorUserId || "system"}</span>
              </div>
              <pre className="log-preview">
                {JSON.stringify(log.metadata || {}, null, 2)}
              </pre>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

export default AdminDashboard;
