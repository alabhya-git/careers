# Secure Job Search and Professional Networking Platform

A full-stack web application for job discovery, professional networking, and recruiter workflows, built with security as a first-class concern. The system enforces confidentiality, integrity, and accountability at every layer — from encrypted resume storage and end-to-end encrypted messaging to PKI-backed authentication and a tamper-evident blockchain audit log.

## 1. Project Summary

The platform supports three user roles — job seekers, recruiters, and platform admins — and provides:

- Secure registration and TOTP-based login.
- User profiles with field-level privacy controls.
- Encrypted resume storage and intelligent job-to-candidate matching.
- Company pages and job postings with full lifecycle management.
- Application tracking with status history.
- End-to-end encrypted private messaging.
- TOTP-protected high-risk actions with a virtual keyboard.
- PKI-backed JWT tokens and signed audit entries.
- A private blockchain-style tamper-evident audit log with proof-of-work.
- Admin dashboard with integrity reporting, user management, and audit log access.

The codebase is split into:

- `backend/` — Express API, cryptographic logic, audit chain, file storage, and role enforcement.
- `frontend/` — React UI for job seekers, recruiters, and admins.

## 2. Technology Stack

### Backend

- Node.js with Express
- `bcryptjs` — password hashing (12 rounds)
- `jsonwebtoken` — signed auth tokens (HS256 fallback, RS256 with PKI)
- `speakeasy` — TOTP generation and verification
- `multer` — secure in-memory file upload handling
- `helmet`, `hpp`, `cors`, `express-rate-limit` — web hardening middleware
- `pdf-parse` — PDF text extraction (v2 class-based API)
- `mammoth` — DOCX text extraction
- Node.js built-in `crypto` — AES-256-GCM encryption, SHA-256, HMAC, RSA signing

### Frontend

- React 19
- Web Crypto API — client-side RSA-2048 keypair generation, AES-GCM message encryption, PBKDF2 key derivation
- React Testing Library — component testing

### Storage Model

- JSON-backed local datastore at `backend/data/db.json`
- Encrypted resume files at `backend/storage/resumes/*.enc`

## 3. User Roles

### Regular User (Job Seeker)

- Register with email, phone, and password; complete TOTP setup on first login.
- Create and edit a profile with field-level privacy (public / connections-only / private).
- Upload a resume (PDF or DOCX); the file is encrypted at rest and parsed for matching signals.
- Search and filter job listings; authenticated users see personalized match scores.
- Apply for jobs with a cover note; track application status through the full pipeline.
- Set up an encrypted messaging identity and communicate with recruiters.
- Reset password or delete account — both require TOTP via the on-screen virtual keyboard.

### Recruiter / Company Admin

- Create and manage company pages (name, description, location, website).
- Post and manage job listings (title, skills, location, salary range, deadline, type).
- Review applicant pools with intelligent match signals (score, matched/missing skills, keyword overlap).
- Update application status and add private recruiter notes.
- Message candidates securely through the encrypted messaging system.

### Platform Admin

- Bootstrapped automatically from environment configuration on first start.
- View platform-wide metrics (users, jobs, applications, conversations).
- Suspend or permanently delete user accounts.
- Access and search the tamper-evident audit log.
- View blockchain integrity status and proof-of-work metrics.

## 4. Feature Reference

### A. User Authentication and Account Security

- **Registration** — collects name, email (normalized), mobile number, password, and role. Passwords must meet a complexity policy (8–64 chars, upper, lower, digit, symbol) and are hashed with bcrypt before storage.
- **Login** — accepts email or phone plus password. On first successful login, the backend issues a TOTP setup challenge (QR code and secret). Subsequent logins require the live 6-digit TOTP code.
- **TOTP** — time-based one-time passwords via `speakeasy` (30-second window). Used for login, password reset, resume download, and account deletion.
- **Virtual keyboard** — an on-screen keyboard is displayed for TOTP entry during high-risk actions (password reset, resume download, account deletion) to mitigate keylogging.
- **Suspended accounts** — blocked at the authorization middleware layer; cannot authenticate or access protected routes.
- **Rate limiting** — 300 requests per 15 minutes globally, 40 per 15 minutes on auth endpoints.

### B. User Profiles and Connections

- Profile fields: name, headline, location, education, experience, skills (comma-separated), profile picture URL, and bio.
- Field-level privacy controls: `public`, `connections`, or `private` per field.
- Profile viewer count and recent viewers list, with opt-out privacy controls.
- Connection requests: send, accept, and remove professional connections.
- Limited connection graph: users see only their direct connections.

### C. Secure Resume Upload and Storage

- Accepts PDF and DOCX files up to 5 MB.
- File type validated by both MIME type and extension before processing.
- File is processed in memory (never written to disk as plaintext).
- Original file encrypted with AES-256-GCM; only the ciphertext, IV, and auth tag are stored on disk.
- Resume download requires authentication and TOTP verification.
- Access control: only the owner, authorized recruiters (with an active application), and platform admins may access a resume.
- Upload event logged to the audit chain.

### D. Resume Parsing and Intelligent Matching

On every upload, the backend runs a text extraction and analysis pipeline in memory:

**Parsing:**
- PDF files parsed with `pdf-parse` (v2) — page count and full text extracted.
- DOCX files parsed with `mammoth` — plain text extracted.
- If parsing fails the upload still succeeds; a warning is attached to the analysis record.

**Analysis signals stored (not raw text):**
- `extractedSkills` — detected from a 41-skill catalog (JavaScript, Python, AWS, Docker, OWASP, etc.)
- `topKeywords` — top 12 non-skill, non-stop-word tokens by frequency
- `yearsOfExperience` — extracted from "N+ years experience" patterns
- `sectionsDetected` — presence of summary, skills, education, experience, projects, certifications, etc.
- `wordCount`, `pageCount`, `parser`, `parsedAt`

**Job matching (score 0–100):**
- Skill overlap with job's `requiredSkills` — 70% weight
- Keyword overlap between resume/profile signals and job description — 20% weight
- Years-of-experience signal when the posting mentions it — 10% weight

**Output per job or application:**
- `score` (integer, 0–100) and `band` (Strong / Good / Potential / Low)
- `matchedSkills` and `missingSkills`
- `keywordHits` — top overlapping keywords
- `explanation` — human-readable summary

**Visible in UI:**
- Job search page — authenticated users see jobs sorted by match score with fit badges.
- My Applications — applicants see their fit score per application.
- Recruiter applicant review — recruiters see match signals for each candidate.
- Resume Vault — users see extracted insights after upload.

### E. Company Pages and Job Postings

- Recruiters create company pages with a unique slug, name, description, location, and website.
- Company admins post job listings: title, description, required skills, workplace type (remote/on-site/hybrid), employment type (full-time/part-time/internship/contract), optional salary range, and application deadline.
- Job listings are publicly searchable by keyword, company, location, skill tag, workplace type, and employment type.
- Company admins can edit and delete their listings.
- Expired deadline detection is applied server-side.

### F. Job Search and Application Tracking

- Authenticated users can apply to any open job with a cover note (requires an uploaded resume).
- Duplicate applications are rejected server-side.
- Application status pipeline: `Applied → Reviewed → Interviewed → Rejected / Offer`.
- Recruiters can shortlist candidates and add private notes.
- Status history is logged as an array of timestamped transitions.
- All status changes are logged to the audit chain.

### G. Secure Messaging

- Users establish a messaging identity by generating an RSA-2048 keypair in the browser.
- The private key is encrypted with a PBKDF2-derived AES-GCM key (250,000 iterations) before upload; the server never sees the plaintext private key.
- Per-conversation AES-256 session keys are generated and wrapped individually for each participant with RSA-OAEP.
- Messages are encrypted client-side with AES-GCM; the server stores only ciphertext, IVs, and encrypted session keys.
- Contact directory is role-aware: job seekers see recruiters from companies they applied to; recruiters see their applicants; admins see all users.
- Direct and small group conversations (up to 6 members).

### H. Admin Dashboard and Moderation

- Platform overview: total users, verified users, recruiters, suspended accounts, resumes uploaded, companies, open jobs, applications, conversations, messages.
- Audit integrity status shown on every dashboard load.
- Blockchain summary: block count, proof-of-work status, difficulty, latest block hash, average nonce.
- Paginated and searchable audit log viewer.
- Suspend / activate user accounts (admin cannot self-suspend).
- Permanently delete user accounts with cascading cleanup (resumes, application records, conversation memberships).

## 5. Security Architecture

### PKI Integration (Two Security-Critical Functions)

**1. JWT Authentication Tokens**
- When `JWT_PRIVATE_KEY` and `JWT_PUBLIC_KEY` are set, auth tokens are signed with RSA-SHA256 (RS256).
- Verification uses the configured public key.
- Falls back to HMAC-SHA256 (HS256) if PKI keys are absent (development mode).
- Token expiry is 2 hours by default.

**2. Audit Log Chain Signatures**
- When `AUDIT_LOG_PRIVATE_KEY` and `AUDIT_LOG_PUBLIC_KEY` are set, each audit record is signed with RSA-SHA256.
- Verification uses the configured public key.
- Falls back to HMAC-SHA256 if PKI keys are absent.
- Chain version is recorded per entry (`PKI_RSA_SHA256_V3` or `HMAC_SHA256_V2`).

### Password Security

- bcrypt with 12 rounds; plaintext passwords are never stored or logged.
- Password complexity enforced at registration and password reset.

### Resume Security

- AES-256-GCM encryption at rest; IV and auth tag stored alongside ciphertext.
- Encryption key loaded from environment; falls back to a SHA-256 hash of a dev-only string.
- Text extraction runs in memory and is discarded after analysis.
- Download requires TOTP; access is checked against ownership and application records.

### Messaging Security

- Client-side RSA-2048 keypair generation using the Web Crypto API.
- Private key never leaves the browser unencrypted.
- Conversation keys are per-conversation, per-member wrapped.
- Server has no access to message plaintext.

### Audit Logging

All critical actions are logged: registration, login, TOTP changes, resume upload and download, application status changes, admin actions (suspension, deletion), and job posting changes.

### Web Attack Defenses

- SQL injection — no SQL database; JSON store with typed access patterns.
- XSS — input sanitized and length-capped server-side; `helmet` sets appropriate response headers.
- CSRF — JWT-based stateless auth (no cookies); same-origin CORS policy.
- Session fixation / hijacking — stateless JWT; no server-side session state.
- Parameter pollution — `hpp` middleware.
- File upload attacks — MIME type and extension double-validation; 5 MB limit; memory-only processing.
- Brute force — rate limiting on global and auth routes.
- Account takeover — TOTP required for high-risk mutations.

## 6. Blockchain-Based Tamper-Evident Audit Log

Every audit entry is simultaneously a signed chain link and a blockchain block:

**Hash chain layer:**
- Each entry stores `prevHash` pointing to the previous entry's signature.
- Each entry's payload is SHA-256 digested (`payloadDigest`).
- The chain link is HMAC-SHA256 or RSA-signed (`signature`).
- The chain is verified by recomputing and comparing at read time.

**Blockchain layer:**
- Each entry carries `blockIndex`, `previousBlockHash`, `blockDifficulty`, `blockNonce`, and `blockHash`.
- `blockHash` is SHA-256 of a canonical block material string including the block index, previous block hash, payload digest, signature, timestamp, and nonce.
- Proof-of-work: the miner increments `blockNonce` until `blockHash` starts with `difficulty` leading zeros.
- Default difficulty is `2` (configurable via `AUDIT_BLOCKCHAIN_DIFFICULTY`).
- Verification recomputes the block hash and checks proof-of-work independently of the signature chain.

**A tampered entry breaks both chains simultaneously** — the signature chain fails because the payload digest no longer matches, and the blockchain layer fails because the block hash no longer satisfies proof-of-work or the previous block hash pointer is wrong.

Admin dashboard exposes: total blocks, signed entries, proof-of-work status, current difficulty, latest block hash, genesis block hash, average nonce, and highest nonce.

## 7. Data Flow

### Registration and Login

1. User submits name, email, phone, password, and role.
2. Server validates inputs and hashes the password with bcrypt.
3. User record is created; an audit event is logged.
4. On first login: server generates a TOTP secret and returns a QR code for enrollment.
5. User scans the QR code, enters the 6-digit code to confirm enrollment.
6. Server issues a signed JWT (RS256 if PKI is configured, HS256 otherwise).

### Resume Upload and Matching

1. User uploads a PDF or DOCX (max 5 MB).
2. Server validates MIME type and extension.
3. File is encrypted with AES-256-GCM; ciphertext written to disk.
4. Text is extracted in memory using `pdf-parse` or `mammoth`.
5. Analysis pipeline runs: skill detection, keyword extraction, experience signals, section detection.
6. Analysis object (no raw text) is stored with the resume metadata.
7. Job search now returns personalized match scores sorted by relevance.

### Encrypted Messaging

1. User generates an RSA-2048 keypair in the browser.
2. Private key is encrypted with PBKDF2+AES-GCM using a user-supplied passphrase.
3. Public key and encrypted private key bundle are uploaded to the server.
4. To send a message: user unlocks the private key with the passphrase.
5. A new AES-256 conversation key is generated; it is wrapped with each participant's RSA public key.
6. Message text is encrypted with the conversation key (AES-GCM).
7. Server stores ciphertext, IV, and per-member wrapped keys; never the plaintext.
8. Recipients decrypt: unwrap conversation key with their private key, then decrypt message.

### Job Application

1. User with an uploaded resume applies to an open job.
2. Application record created with status `Applied`.
3. Recruiter views applicant list; match signals computed from applicant's resume analysis.
4. Recruiter advances status: `Reviewed → Interviewed → Offer / Rejected`.
5. Each status change is timestamped and logged to the audit chain.

## 8. Repository Layout

```
careers/
├── README.md
├── USER_GUIDE.md
├── backend/
│   ├── server.js                  # Express entry point, middleware, route registration
│   ├── .env.example               # Configuration template
│   ├── data/db.json               # JSON datastore
│   ├── storage/resumes/           # AES-256-GCM encrypted resume files
│   └── src/
│       ├── security.js            # bcrypt, TOTP, JWT, AES-GCM, RSA helpers
│       ├── audit.js               # Blockchain-style audit chain (append, verify, summarize)
│       ├── resume-intelligence.js # Resume parsing, skill extraction, job matching
│       ├── portal-helpers.js      # Business logic, serializers, RBAC middleware
│       ├── config.js              # Environment constants
│       ├── store.js               # JSON persistence layer
│       └── routes/
│           ├── auth-profile.js    # Registration, login, profile, resume endpoints
│           ├── opportunities.js   # Companies, jobs, applications
│           ├── messaging.js       # E2EE messaging identity, conversations, messages
│           └── admin.js           # Admin dashboard, user management, audit access
└── frontend/
    └── src/
        ├── App.js                 # Main shell, auth flows, tab navigation
        ├── cryptoUtils.js         # Web Crypto API — keypair, message encryption
        └── components/
            ├── OpportunityHub.js  # Job search, filtering, applying, application tracking
            ├── HiringHub.js       # Recruiter workspace — companies, jobs, applicants
            ├── MessagingHub.js    # E2EE messaging UI
            ├── AdminDashboard.js  # Admin panel — metrics, audit log, user management
            └── VirtualKeyboard.js # On-screen keyboard for TOTP entry
```

## 9. Environment Configuration

Use `backend/.env.example` as the template. Copy it to `backend/.env` and fill in the values.

| Variable | Purpose |
|---|---|
| `PORT` | Backend listen port (default `5000`) |
| `CORS_ORIGIN` | Frontend origin for CORS (default `http://localhost:3000`) |
| `JWT_SECRET` | Fallback HS256 signing secret (development only) |
| `JWT_PRIVATE_KEY` | RSA private key PEM — enables RS256 JWT signing |
| `JWT_PUBLIC_KEY` | RSA public key PEM — enables RS256 JWT verification |
| `AUDIT_LOG_PRIVATE_KEY` | RSA private key PEM — enables PKI audit signing |
| `AUDIT_LOG_PUBLIC_KEY` | RSA public key PEM — enables PKI audit verification |
| `AUDIT_LOG_SIGNING_KEY` | HMAC key for audit chain (fallback when PKI is absent) |
| `AUDIT_BLOCKCHAIN_DIFFICULTY` | Proof-of-work difficulty (number of leading zeros, default `2`) |
| `RESUME_ENCRYPTION_KEY` | 32-byte key as 64-char hex or base64 for AES-256-GCM |
| `DEFAULT_ADMIN_EMAIL` | Bootstrap admin email |
| `DEFAULT_ADMIN_PASSWORD` | Bootstrap admin password |
| `OTP_STEP_SECONDS` | TOTP step size in seconds (default `30`) |
| `OTP_WINDOW` | TOTP validation window (default `1`) |
| `TOTP_ISSUER` | Issuer name shown in authenticator apps |

Frontend:

| Variable | Purpose |
|---|---|
| `REACT_APP_API_BASE_URL` | Optional explicit API base URL (defaults to same-origin) |

## 10. Local Run Instructions

### Backend

```bash
cd backend
npm install
cp .env.example .env   # then edit .env
npm start
```

### Frontend

```bash
cd frontend
npm install
npm start
```

The frontend development server runs on port 3000 and proxies API requests to the backend. For a production deployment, build the frontend and serve it through Nginx alongside the backend, with TLS terminating at the reverse proxy.

### Generating RSA Keys (for PKI mode)

```bash
# Generate a 2048-bit RSA key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Set in .env (replace newlines with \n for single-line values)
# JWT_PRIVATE_KEY and JWT_PUBLIC_KEY for JWT signing
# AUDIT_LOG_PRIVATE_KEY and AUDIT_LOG_PUBLIC_KEY for audit signing
```

## 11. Known Limitations

- The backing datastore is JSON-based for simplicity; it is not suitable for concurrent writes at production scale.
- TLS termination is expected at the reverse proxy (Nginx); the Express server listens on plain HTTP.
- Email and SMS OTP delivery is not implemented; the system uses TOTP (authenticator app) instead.
- Resume intelligence stores only derived matching signals, not raw extracted text, to preserve resume confidentiality.
- The connection graph is a stub; the connections data model exists but a full graph traversal UI is not implemented.
