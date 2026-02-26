
import { useCallback, useEffect, useMemo, useState } from "react";
import "./App.css";

const API_BASE = process.env.REACT_APP_API_BASE_URL || "http://localhost:5000";
const LOCAL_TOKEN_KEY = "job_portal_token";

const PROFILE_PRIVACY_KEYS = [
  "headline",
  "location",
  "education",
  "experience",
  "skills",
  "bio",
];

const defaultRegisterForm = {
  name: "",
  email: "",
  mobile: "",
  password: "",
  role: "user",
};

const defaultProfileForm = {
  name: "",
  headline: "",
  location: "",
  education: "",
  experience: "",
  skills: "",
  profilePicture: "",
  bio: "",
};

const defaultPrivacyForm = {
  headline: "public",
  location: "connections",
  education: "connections",
  experience: "connections",
  skills: "public",
  bio: "public",
};

const defaultForgotForm = {
  identifierType: "email",
  identifier: "",
  channel: "email",
  otp: "",
  newPassword: "",
  confirmPassword: "",
};

const defaultResetState = {
  channel: "email",
  otp: "",
  newPassword: "",
  confirmPassword: "",
};

const defaultDeleteState = {
  channel: "email",
  otp: "",
};

function normalizeIdentifier(identifierType, value) {
  const raw = String(value || "").trim();
  if (identifierType === "mobile") {
    return raw.replace(/[^\d]/g, "");
  }

  return raw.toLowerCase();
}

function formatDate(value) {
  if (!value) {
    return "-";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }

  return date.toLocaleString();
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

function App() {
  const [token, setToken] = useState(() => localStorage.getItem(LOCAL_TOKEN_KEY) || "");
  const [currentUser, setCurrentUser] = useState(null);
  const [activeTab, setActiveTab] = useState("profile");

  const [authView, setAuthView] = useState("login");
  const [loginStage, setLoginStage] = useState("credentials");
  const [pendingLogin, setPendingLogin] = useState(null);
  const [loginOtpHint, setLoginOtpHint] = useState("");

  const [statusMessage, setStatusMessage] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [latestDevOtp, setLatestDevOtp] = useState(null);
  const [isBusy, setIsBusy] = useState(false);

  const [loginForm, setLoginForm] = useState({
    identifierType: "email",
    identifier: "",
    password: "",
    channel: "email",
  });
  const [loginOtp, setLoginOtp] = useState("");

  const [registerForm, setRegisterForm] = useState(defaultRegisterForm);
  const [forgotStage, setForgotStage] = useState("request");
  const [forgotForm, setForgotForm] = useState(defaultForgotForm);

  const [profileForm, setProfileForm] = useState(defaultProfileForm);
  const [privacyForm, setPrivacyForm] = useState(defaultPrivacyForm);

  const [resumeFile, setResumeFile] = useState(null);
  const [resumeInfo, setResumeInfo] = useState(null);
  const [downloadChannel, setDownloadChannel] = useState("email");
  const [downloadOtp, setDownloadOtp] = useState("");

  const [securityReset, setSecurityReset] = useState(defaultResetState);
  const [securityDelete, setSecurityDelete] = useState(defaultDeleteState);

  const [adminOverview, setAdminOverview] = useState(null);
  const [adminUsers, setAdminUsers] = useState([]);

  const clearFeedback = useCallback(() => {
    setStatusMessage("");
    setErrorMessage("");
  }, []);

  const request = useCallback(
    async (
      endpoint,
      { method = "GET", body, auth = false, asFormData = false, responseType = "json" } = {}
    ) => {
      const headers = {};
      if (!asFormData) {
        headers["Content-Type"] = "application/json";
      }

      if (auth && token) {
        headers.Authorization = `Bearer ${token}`;
      }

      const response = await fetch(`${API_BASE}${endpoint}`, {
        method,
        headers,
        body: asFormData ? body : body ? JSON.stringify(body) : undefined,
      });

      if (responseType === "blob") {
        if (!response.ok) {
          const failedPayload = await response.json().catch(() => ({}));
          throw new Error(failedPayload.message || "Request failed.");
        }

        return {
          blob: await response.blob(),
          headers: response.headers,
        };
      }

      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.message || "Request failed.");
      }

      return payload;
    },
    [token]
  );

  const resetAuthFlow = useCallback(() => {
    setAuthView("login");
    setLoginStage("credentials");
    setPendingLogin(null);
    setLoginOtp("");
    setLoginOtpHint("");
    setForgotStage("request");
    setForgotForm(defaultForgotForm);
  }, []);

  const logout = useCallback(() => {
    setToken("");
    setCurrentUser(null);
    setActiveTab("profile");
    setLatestDevOtp(null);
    resetAuthFlow();
  }, [resetAuthFlow]);

  const loadCurrentUser = useCallback(async () => {
    if (!token) {
      return;
    }

    const data = await request("/api/auth/me", { auth: true });
    setCurrentUser(data.user);
    setActiveTab((previous) => {
      if (data.user.role === "admin" && previous === "admin") {
        return "admin";
      }

      if (data.user.role !== "admin" && previous === "admin") {
        return "profile";
      }

      return previous;
    });
  }, [request, token]);

  const loadProfile = useCallback(async () => {
    const data = await request("/api/profile/me", { auth: true });
    const profile = data.profile || {};

    setProfileForm({
      name: profile.name || "",
      headline: profile.headline || "",
      location: profile.location || "",
      education: profile.education || "",
      experience: profile.experience || "",
      skills: Array.isArray(profile.skills) ? profile.skills.join(", ") : "",
      profilePicture: profile.profilePicture || "",
      bio: profile.bio || "",
    });

    setPrivacyForm({
      ...defaultPrivacyForm,
      ...(profile.privacy || {}),
    });
  }, [request]);

  const loadResume = useCallback(async () => {
    const data = await request("/api/resume/me", { auth: true });
    setResumeInfo(data.resume || null);
  }, [request]);

  const loadAdminDashboard = useCallback(async () => {
    const [overviewResult, usersResult] = await Promise.all([
      request("/api/admin/overview", { auth: true }),
      request("/api/admin/users", { auth: true }),
    ]);

    setAdminOverview(overviewResult);
    setAdminUsers(usersResult.users || []);
  }, [request]);

  useEffect(() => {
    if (token) {
      localStorage.setItem(LOCAL_TOKEN_KEY, token);
    } else {
      localStorage.removeItem(LOCAL_TOKEN_KEY);
    }
  }, [token]);

  useEffect(() => {
    if (!token) {
      return;
    }

    loadCurrentUser().catch((error) => {
      logout();
      setErrorMessage(error.message);
    });
  }, [token, loadCurrentUser, logout]);

  useEffect(() => {
    if (!token || !currentUser) {
      return;
    }

    const run = async () => {
      if (activeTab === "profile") {
        await loadProfile();
      }

      if (activeTab === "resume") {
        await loadResume();
      }

      if (activeTab === "admin" && currentUser.role === "admin") {
        await loadAdminDashboard();
      }
    };

    run().catch((error) => {
      setErrorMessage(error.message);
    });
  }, [
    token,
    currentUser,
    activeTab,
    loadProfile,
    loadResume,
    loadAdminDashboard,
  ]);

  const handleRegister = async (event) => {
    event.preventDefault();
    clearFeedback();
    setIsBusy(true);

    try {
      const payload = await request("/api/auth/register", {
        method: "POST",
        body: registerForm,
      });

      setStatusMessage(payload.message || "Account created.");
      setLatestDevOtp(null);
      setAuthView("login");
      setLoginStage("credentials");
      setLoginForm((previous) => ({
        ...previous,
        identifierType: "email",
        identifier: registerForm.email,
      }));
      setRegisterForm(defaultRegisterForm);
    } catch (error) {
      setErrorMessage(error.message);
    } finally {
      setIsBusy(false);
    }
  };

  const handleLoginCredentials = async (event) => {
    event.preventDefault();
    clearFeedback();
    setIsBusy(true);

    try {
      const identifier = normalizeIdentifier(
        loginForm.identifierType,
        loginForm.identifier
      );

      const payload = await request("/api/auth/login", {
        method: "POST",
        body: {
          identifier,
          password: loginForm.password,
          channel: loginForm.channel,
        },
      });

      if (payload.token) {
        setToken(payload.token);
        setCurrentUser(payload.user);
        setStatusMessage("Login successful.");
        setLatestDevOtp(null);
        return;
      }

      setPendingLogin({
        identifier,
        password: loginForm.password,
        channel: loginForm.channel,
      });
      setLoginOtpHint(payload.deliveryHint || "");
      setLoginStage("otp");
      setStatusMessage(payload.message || "OTP sent. Enter it to continue.");
      if (payload.devOtp) {
        setLatestDevOtp({ [loginForm.channel]: payload.devOtp });
      }
    } catch (error) {
      setErrorMessage(error.message);
    } finally {
      setIsBusy(false);
    }
  };

  const handleLoginOtpSubmit = async (event) => {
    event.preventDefault();
    clearFeedback();

    if (!pendingLogin) {
      setLoginStage("credentials");
      return;
    }

    setIsBusy(true);

    try {
      const payload = await request("/api/auth/login", {
        method: "POST",
        body: {
          ...pendingLogin,
          otp: loginOtp,
        },
      });

      setToken(payload.token);
      setCurrentUser(payload.user);
      setStatusMessage("Login successful.");
      setLatestDevOtp(null);
      setLoginOtp("");
      setPendingLogin(null);
      setLoginStage("credentials");
    } catch (error) {
      setErrorMessage(`${error.message} Please login again.`);
      setPendingLogin(null);
      setLoginOtp("");
      setLoginStage("credentials");
      setLatestDevOtp(null);
    } finally {
      setIsBusy(false);
    }
  };

  const handleForgotRequest = async (event) => {
    event.preventDefault();
    clearFeedback();
    setIsBusy(true);

    try {
      const identifier = normalizeIdentifier(
        forgotForm.identifierType,
        forgotForm.identifier
      );

      const payload = await request("/api/auth/password-reset/request", {
        method: "POST",
        body: {
          identifier,
          channel: forgotForm.channel,
        },
      });

      setStatusMessage(payload.message || "Reset OTP sent.");
      setForgotStage("confirm");
      setForgotForm((previous) => ({
        ...previous,
        identifier,
      }));
      if (payload.devOtp) {
        setLatestDevOtp({ [forgotForm.channel]: payload.devOtp });
      }
    } catch (error) {
      setErrorMessage(error.message);
    } finally {
      setIsBusy(false);
    }
  };

  const handleForgotConfirm = async (event) => {
    event.preventDefault();
    clearFeedback();

    if (forgotForm.newPassword !== forgotForm.confirmPassword) {
      setErrorMessage("New password and confirm password must match.");
      return;
    }

    setIsBusy(true);

    try {
      const payload = await request("/api/auth/password-reset/confirm", {
        method: "POST",
        body: {
          identifier: forgotForm.identifier,
          channel: forgotForm.channel,
          otp: forgotForm.otp,
          newPassword: forgotForm.newPassword,
        },
      });

      setStatusMessage(payload.message || "Password reset successful.");
      setAuthView("login");
      setForgotStage("request");
      setForgotForm(defaultForgotForm);
      setLatestDevOtp(null);
    } catch (error) {
      setErrorMessage(error.message);
    } finally {
      setIsBusy(false);
    }
  };

  const handleProfileSave = async (event) => {
    event.preventDefault();
    clearFeedback();
    setIsBusy(true);

    try {
      const payload = await request("/api/profile/me", {
        method: "PUT",
        auth: true,
        body: {
          ...profileForm,
          skills: profileForm.skills,
          privacy: privacyForm,
        },
      });

      setProfileForm((previous) => ({
        ...previous,
        skills: Array.isArray(payload.profile?.skills)
          ? payload.profile.skills.join(", ")
          : previous.skills,
      }));

      setStatusMessage(payload.message || "Profile updated.");
      await loadCurrentUser();
    } catch (error) {
      setErrorMessage(error.message);
    } finally {
      setIsBusy(false);
    }
  };

  const handleResumeUpload = async (event) => {
    event.preventDefault();
    clearFeedback();

    if (!resumeFile) {
      setErrorMessage("Select a resume file first.");
      return;
    }

    setIsBusy(true);

    try {
      const formData = new FormData();
      formData.append("resume", resumeFile);

      const payload = await request("/api/resume/upload", {
        method: "POST",
        auth: true,
        asFormData: true,
        body: formData,
      });

      setResumeInfo(payload.resume || null);
      setStatusMessage(payload.message || "Resume uploaded and encrypted.");
      setResumeFile(null);
    } catch (error) {
      setErrorMessage(error.message);
    } finally {
      setIsBusy(false);
    }
  };

  const handleRequestDownloadOtp = async () => {
    clearFeedback();
    setIsBusy(true);

    try {
      const payload = await request("/api/resume/request-download-otp", {
        method: "POST",
        auth: true,
        body: { channel: downloadChannel },
      });

      setStatusMessage(payload.message || "Download OTP sent.");
      if (payload.devOtp) {
        setLatestDevOtp({ [downloadChannel]: payload.devOtp });
      }
    } catch (error) {
      setErrorMessage(error.message);
    } finally {
      setIsBusy(false);
    }
  };

  const handleDownloadResume = async () => {
    clearFeedback();
    setIsBusy(true);

    try {
      const result = await request("/api/resume/download", {
        method: "POST",
        auth: true,
        body: {
          channel: downloadChannel,
          otp: downloadOtp,
        },
        responseType: "blob",
      });

      const fallbackName = resumeInfo?.originalName || "resume";
      const contentDisposition = result.headers.get("content-disposition") || "";
      const matched = contentDisposition.match(/filename="?([^"]+)"?/i);
      const downloadName = matched?.[1] || fallbackName;

      const url = URL.createObjectURL(result.blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = downloadName;
      link.click();
      URL.revokeObjectURL(url);

      setStatusMessage("Resume downloaded.");
      setDownloadOtp("");
    } catch (error) {
      setErrorMessage(error.message);
    } finally {
      setIsBusy(false);
    }
  };

  const handleSecurityPasswordResetOtp = async () => {
    clearFeedback();
    setIsBusy(true);

    try {
      const identifier =
        securityReset.channel === "email" ? currentUser.email : currentUser.mobile;

      const payload = await request("/api/auth/password-reset/request", {
        method: "POST",
        body: {
          identifier,
          channel: securityReset.channel,
        },
      });

      setStatusMessage(payload.message || "Password reset OTP sent.");
      if (payload.devOtp) {
        setLatestDevOtp({ [securityReset.channel]: payload.devOtp });
      }
    } catch (error) {
      setErrorMessage(error.message);
    } finally {
      setIsBusy(false);
    }
  };

  const handleSecurityPasswordResetConfirm = async (event) => {
    event.preventDefault();
    clearFeedback();

    if (securityReset.newPassword !== securityReset.confirmPassword) {
      setErrorMessage("New password and confirm password must match.");
      return;
    }

    setIsBusy(true);

    try {
      const identifier =
        securityReset.channel === "email" ? currentUser.email : currentUser.mobile;

      const payload = await request("/api/auth/password-reset/confirm", {
        method: "POST",
        body: {
          identifier,
          channel: securityReset.channel,
          otp: securityReset.otp,
          newPassword: securityReset.newPassword,
        },
      });

      setStatusMessage(payload.message || "Password reset successful.");
      setSecurityReset(defaultResetState);
      setLatestDevOtp(null);
    } catch (error) {
      setErrorMessage(error.message);
    } finally {
      setIsBusy(false);
    }
  };

  const handleRequestAccountDeletionOtp = async () => {
    clearFeedback();
    setIsBusy(true);

    try {
      const payload = await request("/api/account/request-deletion-otp", {
        method: "POST",
        auth: true,
        body: { channel: securityDelete.channel },
      });

      setStatusMessage(payload.message || "Account deletion OTP sent.");
      if (payload.devOtp) {
        setLatestDevOtp({ [securityDelete.channel]: payload.devOtp });
      }
    } catch (error) {
      setErrorMessage(error.message);
    } finally {
      setIsBusy(false);
    }
  };

  const handleAccountDeletion = async (event) => {
    event.preventDefault();
    clearFeedback();
    setIsBusy(true);

    try {
      const payload = await request("/api/account/delete", {
        method: "POST",
        auth: true,
        body: {
          channel: securityDelete.channel,
          otp: securityDelete.otp,
        },
      });

      logout();
      setStatusMessage(payload.message || "Account deleted.");
      setSecurityDelete(defaultDeleteState);
    } catch (error) {
      setErrorMessage(error.message);
    } finally {
      setIsBusy(false);
    }
  };

  const toggleUserSuspension = async (user) => {
    clearFeedback();
    setIsBusy(true);

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

      setStatusMessage(payload.message || "User status updated.");
      await loadAdminDashboard();
    } catch (error) {
      setErrorMessage(error.message);
    } finally {
      setIsBusy(false);
    }
  };

  const deleteUser = async (userId) => {
    clearFeedback();
    setIsBusy(true);

    try {
      const payload = await request(`/api/admin/users/${userId}`, {
        method: "DELETE",
        auth: true,
      });

      setStatusMessage(payload.message || "User deleted.");
      await loadAdminDashboard();
    } catch (error) {
      setErrorMessage(error.message);
    } finally {
      setIsBusy(false);
    }
  };

  const adminTotals = useMemo(() => adminOverview?.totals || {}, [adminOverview]);

  return (
    <div className="app-shell">
      <div className="orb orb-one" />
      <div className="orb orb-two" />

      <header className="topbar">
        <div>
          <h1>Damera Corp. Careers Portal</h1>
        </div>

        {currentUser ? (
          <div className="session">
            <span>
              {currentUser.profile?.name || currentUser.email} ({prettyRole(currentUser.role)})
            </span>
            <button type="button" className="btn btn-ghost" onClick={logout}>
              Logout
            </button>
          </div>
        ) : (
          <span className="badge">Guest</span>
        )}
      </header>

      {statusMessage && <div className="alert success">{statusMessage}</div>}
      {errorMessage && <div className="alert error">{errorMessage}</div>}
      {latestDevOtp && (
        <div className="alert info">Dev OTP: {JSON.stringify(latestDevOtp)}</div>
      )}

      {!currentUser ? (
        <main className="auth-stage">
          <section className="hero-copy">
            <h2>Secure access for your next career move.</h2>
            <p>
              Clean two-step login, encrypted resumes, and OTP-protected critical actions.
            </p>
          </section>

          {authView === "login" && (
            <section className="auth-card">
              {loginStage === "credentials" ? (
                <>
                  <h3>Login</h3>
                  <form onSubmit={handleLoginCredentials}>
                    <label>
                      Sign in with
                      <select
                        value={loginForm.identifierType}
                        onChange={(event) =>
                          setLoginForm((previous) => ({
                            ...previous,
                            identifierType: event.target.value,
                          }))
                        }
                      >
                        <option value="email">Email</option>
                        <option value="mobile">Phone</option>
                      </select>
                    </label>

                    <label>
                      {loginForm.identifierType === "email" ? "Email" : "Phone"}
                      <input
                        type={loginForm.identifierType === "email" ? "email" : "text"}
                        value={loginForm.identifier}
                        onChange={(event) =>
                          setLoginForm((previous) => ({
                            ...previous,
                            identifier: event.target.value,
                          }))
                        }
                        required
                      />
                    </label>

                    <label>
                      Password
                      <input
                        type="password"
                        value={loginForm.password}
                        onChange={(event) =>
                          setLoginForm((previous) => ({
                            ...previous,
                            password: event.target.value,
                          }))
                        }
                        required
                      />
                    </label>

                    <label>
                      OTP Channel
                      <select
                        value={loginForm.channel}
                        onChange={(event) =>
                          setLoginForm((previous) => ({
                            ...previous,
                            channel: event.target.value,
                          }))
                        }
                      >
                        <option value="email">Email OTP</option>
                        <option value="mobile">SMS OTP</option>
                      </select>
                    </label>

                    <button className="btn" type="submit" disabled={isBusy}>
                      Continue
                    </button>
                  </form>

                  <button
                    type="button"
                    className="text-link"
                    onClick={() => {
                      setAuthView("forgot");
                      clearFeedback();
                    }}
                  >
                    Forgot password?
                  </button>

                  <p className="switch-note">
                    Not a user?{" "}
                    <button
                      type="button"
                      className="text-link inline"
                      onClick={() => {
                        setAuthView("register");
                        clearFeedback();
                      }}
                    >
                      Register here
                    </button>
                  </p>
                </>
              ) : (
                <>
                  <h3>Enter OTP</h3>
                  <p className="muted-copy">
                    OTP sent to {loginOtpHint || "your selected channel"}.
                  </p>
                  <form onSubmit={handleLoginOtpSubmit}>
                    <label>
                      One-time password
                      <input
                        value={loginOtp}
                        onChange={(event) => setLoginOtp(event.target.value)}
                        required
                      />
                    </label>

                    <div className="stack-actions">
                      <button className="btn" type="submit" disabled={isBusy}>
                        Verify and Login
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost"
                        onClick={() => {
                          setLoginStage("credentials");
                          setPendingLogin(null);
                          setLoginOtp("");
                          setLoginOtpHint("");
                          setLatestDevOtp(null);
                        }}
                        disabled={isBusy}
                      >
                        Back
                      </button>
                    </div>
                  </form>
                </>
              )}
            </section>
          )}

          {authView === "register" && (
            <section className="auth-card">
              <h3>Create Account</h3>
              <form onSubmit={handleRegister}>
                <label>
                  Full Name
                  <input
                    value={registerForm.name}
                    onChange={(event) =>
                      setRegisterForm((previous) => ({
                        ...previous,
                        name: event.target.value,
                      }))
                    }
                    required
                  />
                </label>

                <label>
                  Email
                  <input
                    type="email"
                    value={registerForm.email}
                    onChange={(event) =>
                      setRegisterForm((previous) => ({
                        ...previous,
                        email: event.target.value,
                      }))
                    }
                    required
                  />
                </label>

                <label>
                  Mobile
                  <input
                    value={registerForm.mobile}
                    onChange={(event) =>
                      setRegisterForm((previous) => ({
                        ...previous,
                        mobile: event.target.value,
                      }))
                    }
                    required
                  />
                </label>

                <label>
                  Password
                  <input
                    type="password"
                    value={registerForm.password}
                    onChange={(event) =>
                      setRegisterForm((previous) => ({
                        ...previous,
                        password: event.target.value,
                      }))
                    }
                    required
                  />
                </label>

                <label>
                  Role
                  <select
                    value={registerForm.role}
                    onChange={(event) =>
                      setRegisterForm((previous) => ({
                        ...previous,
                        role: event.target.value,
                      }))
                    }
                  >
                    <option value="user">Regular User</option>
                    <option value="recruiter">Recruiter</option>
                  </select>
                </label>

                <button className="btn" type="submit" disabled={isBusy}>
                  Register
                </button>
              </form>

              <p className="switch-note">
                Already a user?{" "}
                <button
                  type="button"
                  className="text-link inline"
                  onClick={() => {
                    setAuthView("login");
                    clearFeedback();
                  }}
                >
                  Login
                </button>
              </p>
            </section>
          )}

          {authView === "forgot" && (
            <section className="auth-card">
              <h3>Password Reset</h3>

              {forgotStage === "request" ? (
                <form onSubmit={handleForgotRequest}>
                  <label>
                    Account Type
                    <select
                      value={forgotForm.identifierType}
                      onChange={(event) =>
                        setForgotForm((previous) => ({
                          ...previous,
                          identifierType: event.target.value,
                        }))
                      }
                    >
                      <option value="email">Email</option>
                      <option value="mobile">Phone</option>
                    </select>
                  </label>

                  <label>
                    {forgotForm.identifierType === "email" ? "Email" : "Phone"}
                    <input
                      type={forgotForm.identifierType === "email" ? "email" : "text"}
                      value={forgotForm.identifier}
                      onChange={(event) =>
                        setForgotForm((previous) => ({
                          ...previous,
                          identifier: event.target.value,
                        }))
                      }
                      required
                    />
                  </label>

                  <label>
                    OTP Channel
                    <select
                      value={forgotForm.channel}
                      onChange={(event) =>
                        setForgotForm((previous) => ({
                          ...previous,
                          channel: event.target.value,
                        }))
                      }
                    >
                      <option value="email">Email OTP</option>
                      <option value="mobile">SMS OTP</option>
                    </select>
                  </label>

                  <button className="btn" type="submit" disabled={isBusy}>
                    Send OTP
                  </button>
                </form>
              ) : (
                <form onSubmit={handleForgotConfirm}>
                  <label>
                    OTP
                    <input
                      value={forgotForm.otp}
                      onChange={(event) =>
                        setForgotForm((previous) => ({
                          ...previous,
                          otp: event.target.value,
                        }))
                      }
                      required
                    />
                  </label>

                  <label>
                    New Password
                    <input
                      type="password"
                      value={forgotForm.newPassword}
                      onChange={(event) =>
                        setForgotForm((previous) => ({
                          ...previous,
                          newPassword: event.target.value,
                        }))
                      }
                      required
                    />
                  </label>

                  <label>
                    Confirm Password
                    <input
                      type="password"
                      value={forgotForm.confirmPassword}
                      onChange={(event) =>
                        setForgotForm((previous) => ({
                          ...previous,
                          confirmPassword: event.target.value,
                        }))
                      }
                      required
                    />
                  </label>

                  <button className="btn" type="submit" disabled={isBusy}>
                    Reset Password
                  </button>
                </form>
              )}

              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => {
                  if (forgotStage === "confirm") {
                    setForgotStage("request");
                    setForgotForm((previous) => ({
                      ...previous,
                      otp: "",
                      newPassword: "",
                      confirmPassword: "",
                    }));
                    return;
                  }

                  setAuthView("login");
                }}
              >
                Back
              </button>
            </section>
          )}
        </main>
      ) : (
        <main className="workspace">
          <nav className="tabs">
            <button
              type="button"
              className={`tab ${activeTab === "profile" ? "active" : ""}`}
              onClick={() => setActiveTab("profile")}
            >
              Profile
            </button>
            <button
              type="button"
              className={`tab ${activeTab === "resume" ? "active" : ""}`}
              onClick={() => setActiveTab("resume")}
            >
              Resume Vault
            </button>
            <button
              type="button"
              className={`tab ${activeTab === "security" ? "active" : ""}`}
              onClick={() => setActiveTab("security")}
            >
              Security
            </button>
            {currentUser.role === "admin" && (
              <button
                type="button"
                className={`tab ${activeTab === "admin" ? "active" : ""}`}
                onClick={() => setActiveTab("admin")}
              >
                Admin
              </button>
            )}
          </nav>

          {activeTab === "profile" && (
            <section className="panel wide">
              <h2>Profile</h2>
              <form onSubmit={handleProfileSave}>
                <div className="grid-two">
                  <label>
                    Name
                    <input
                      value={profileForm.name}
                      onChange={(event) =>
                        setProfileForm((previous) => ({
                          ...previous,
                          name: event.target.value,
                        }))
                      }
                    />
                  </label>

                  <label>
                    Headline
                    <input
                      value={profileForm.headline}
                      onChange={(event) =>
                        setProfileForm((previous) => ({
                          ...previous,
                          headline: event.target.value,
                        }))
                      }
                    />
                  </label>

                  <label>
                    Location
                    <input
                      value={profileForm.location}
                      onChange={(event) =>
                        setProfileForm((previous) => ({
                          ...previous,
                          location: event.target.value,
                        }))
                      }
                    />
                  </label>

                  <label>
                    Profile Image URL
                    <input
                      value={profileForm.profilePicture}
                      onChange={(event) =>
                        setProfileForm((previous) => ({
                          ...previous,
                          profilePicture: event.target.value,
                        }))
                      }
                    />
                  </label>
                </div>

                <label>
                  Education
                  <textarea
                    rows="3"
                    value={profileForm.education}
                    onChange={(event) =>
                      setProfileForm((previous) => ({
                        ...previous,
                        education: event.target.value,
                      }))
                    }
                  />
                </label>

                <label>
                  Experience
                  <textarea
                    rows="4"
                    value={profileForm.experience}
                    onChange={(event) =>
                      setProfileForm((previous) => ({
                        ...previous,
                        experience: event.target.value,
                      }))
                    }
                  />
                </label>

                <label>
                  Skills (comma-separated)
                  <input
                    value={profileForm.skills}
                    onChange={(event) =>
                      setProfileForm((previous) => ({
                        ...previous,
                        skills: event.target.value,
                      }))
                    }
                  />
                </label>

                <label>
                  Bio
                  <textarea
                    rows="4"
                    value={profileForm.bio}
                    onChange={(event) =>
                      setProfileForm((previous) => ({
                        ...previous,
                        bio: event.target.value,
                      }))
                    }
                  />
                </label>

                <h3>Privacy</h3>
                <div className="grid-two">
                  {PROFILE_PRIVACY_KEYS.map((key) => (
                    <label key={key}>
                      {key}
                      <select
                        value={privacyForm[key]}
                        onChange={(event) =>
                          setPrivacyForm((previous) => ({
                            ...previous,
                            [key]: event.target.value,
                          }))
                        }
                      >
                        <option value="public">Public</option>
                        <option value="connections">Connections</option>
                        <option value="private">Private</option>
                      </select>
                    </label>
                  ))}
                </div>

                <button className="btn" type="submit" disabled={isBusy}>
                  Save Profile
                </button>
              </form>
            </section>
          )}

          {activeTab === "resume" && (
            <section className="panel wide">
              <h2>Resume Vault</h2>
              <p className="muted-copy">Uploads are encrypted before being stored on server disk.</p>

              <form onSubmit={handleResumeUpload}>
                <label>
                  Upload Resume (PDF/DOCX, max 5MB)
                  <input
                    type="file"
                    accept=".pdf,.docx"
                    onChange={(event) => setResumeFile(event.target.files?.[0] || null)}
                  />
                </label>

                <button className="btn" type="submit" disabled={isBusy}>
                  Upload Encrypted Resume
                </button>
              </form>

              {resumeInfo && (
                <div className="summary-card">
                  <h3>Stored Resume</h3>
                  <p>{resumeInfo.originalName}</p>
                  <p>{resumeInfo.algorithm} at rest</p>
                  <p>{formatDate(resumeInfo.uploadedAt)}</p>
                </div>
              )}

              <div className="download-tools">
                <label>
                  Download OTP Channel
                  <select
                    value={downloadChannel}
                    onChange={(event) => setDownloadChannel(event.target.value)}
                  >
                    <option value="email">Email OTP</option>
                    <option value="mobile">SMS OTP</option>
                  </select>
                </label>

                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={handleRequestDownloadOtp}
                  disabled={isBusy || !resumeInfo}
                >
                  Send Download OTP
                </button>

                <label>
                  OTP
                  <input
                    value={downloadOtp}
                    onChange={(event) => setDownloadOtp(event.target.value)}
                    placeholder="Enter OTP"
                  />
                </label>

                <button
                  type="button"
                  className="btn"
                  onClick={handleDownloadResume}
                  disabled={isBusy || !resumeInfo || !downloadOtp}
                >
                  Download Resume
                </button>
              </div>
            </section>
          )}

          {activeTab === "security" && (
            <section className="panel wide">
              <h2>Security Actions</h2>

              <div className="security-grid">
                <article className="security-card">
                  <h3>Password Reset</h3>
                  <p className="muted-copy">OTP required for changing your password.</p>
                  <form onSubmit={handleSecurityPasswordResetConfirm}>
                    <label>
                      OTP Channel
                      <select
                        value={securityReset.channel}
                        onChange={(event) =>
                          setSecurityReset((previous) => ({
                            ...previous,
                            channel: event.target.value,
                          }))
                        }
                      >
                        <option value="email">Email OTP</option>
                        <option value="mobile">SMS OTP</option>
                      </select>
                    </label>

                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={handleSecurityPasswordResetOtp}
                      disabled={isBusy}
                    >
                      Send Reset OTP
                    </button>

                    <label>
                      OTP
                      <input
                        value={securityReset.otp}
                        onChange={(event) =>
                          setSecurityReset((previous) => ({
                            ...previous,
                            otp: event.target.value,
                          }))
                        }
                        required
                      />
                    </label>

                    <label>
                      New Password
                      <input
                        type="password"
                        value={securityReset.newPassword}
                        onChange={(event) =>
                          setSecurityReset((previous) => ({
                            ...previous,
                            newPassword: event.target.value,
                          }))
                        }
                        required
                      />
                    </label>

                    <label>
                      Confirm Password
                      <input
                        type="password"
                        value={securityReset.confirmPassword}
                        onChange={(event) =>
                          setSecurityReset((previous) => ({
                            ...previous,
                            confirmPassword: event.target.value,
                          }))
                        }
                        required
                      />
                    </label>

                    <button className="btn" type="submit" disabled={isBusy}>
                      Confirm Password Reset
                    </button>
                  </form>
                </article>

                <article className="security-card danger-zone">
                  <h3>Delete Account</h3>
                  <p className="muted-copy">
                    This is permanent. OTP verification is mandatory.
                  </p>

                  <form onSubmit={handleAccountDeletion}>
                    <label>
                      OTP Channel
                      <select
                        value={securityDelete.channel}
                        onChange={(event) =>
                          setSecurityDelete((previous) => ({
                            ...previous,
                            channel: event.target.value,
                          }))
                        }
                      >
                        <option value="email">Email OTP</option>
                        <option value="mobile">SMS OTP</option>
                      </select>
                    </label>

                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={handleRequestAccountDeletionOtp}
                      disabled={isBusy}
                    >
                      Send Deletion OTP
                    </button>

                    <label>
                      OTP
                      <input
                        value={securityDelete.otp}
                        onChange={(event) =>
                          setSecurityDelete((previous) => ({
                            ...previous,
                            otp: event.target.value,
                          }))
                        }
                        required
                      />
                    </label>

                    <button className="btn btn-danger" type="submit" disabled={isBusy}>
                      Delete My Account
                    </button>
                  </form>
                </article>
              </div>
            </section>
          )}

          {activeTab === "admin" && currentUser.role === "admin" && (
            <section className="panel wide">
              <h2>Admin Dashboard</h2>

              <div className="kpi-grid">
                <div className="kpi">
                  <span>Total Users</span>
                  <strong>{adminTotals.totalUsers || 0}</strong>
                </div>
                <div className="kpi">
                  <span>Verified Users</span>
                  <strong>{adminTotals.verifiedUsers || 0}</strong>
                </div>
                <div className="kpi">
                  <span>Recruiters</span>
                  <strong>{adminTotals.recruiterUsers || 0}</strong>
                </div>
                <div className="kpi">
                  <span>Suspended</span>
                  <strong>{adminTotals.suspendedUsers || 0}</strong>
                </div>
                <div className="kpi">
                  <span>Resumes</span>
                  <strong>{adminTotals.resumesUploaded || 0}</strong>
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
                    {adminUsers.map((user) => (
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
                              disabled={isBusy || user.id === currentUser.id}
                            >
                              {user.isSuspended ? "Activate" : "Suspend"}
                            </button>
                            <button
                              type="button"
                              className="btn btn-danger"
                              onClick={() => deleteUser(user.id)}
                              disabled={isBusy || user.id === currentUser.id}
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
            </section>
          )}
        </main>
      )}
    </div>
  );
}

export default App;
