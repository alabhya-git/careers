# User Guide

This guide explains how to use the Secure Job Search and Professional Networking Platform from the perspective of each role: job seeker, recruiter, and platform admin.

## 1. Before You Start

### What you need

- A browser with JavaScript enabled
- Access to the frontend application
- Access to the backend API through the configured environment
- An authenticator app such as Google Authenticator or Microsoft Authenticator

### Important security behavior

- Login uses password plus TOTP.
- High-risk actions require a TOTP code entered through the on-screen keyboard.
- Resume files are stored encrypted.
- Private messages are encrypted in the browser.

## 2. Common Navigation

After login, the top navigation tabs will change based on your role.

### Tabs available to most users

- `Profile`
- `Resume Vault`
- `Opportunities`
- `Messages`
- `Security`

### Additional tabs for recruiters/admins

- `Hiring`

### Additional tab for platform admins

- `Admin`

## 3. Job Seeker Guide

## 3.1 Register a New Account

1. Open the application landing page.
2. Choose `Register`.
3. Enter:
   - name
   - email
   - mobile number
   - password
   - role = `user`
4. Submit the form.

Password requirements:

- 8 to 64 characters
- at least one uppercase letter
- at least one lowercase letter
- at least one number
- at least one symbol

## 3.2 First Login and Authenticator Setup

1. Choose `Login`.
2. Enter your email or phone and password.
3. On first login, the system will require authenticator setup.
4. Scan the QR code with your authenticator app.
5. Enter the current 6-digit code from the authenticator app.
6. After validation, you will be logged in.

Tip:

- Keep your authenticator app available, because the same TOTP is needed for password reset, resume download, and account deletion.

## 3.3 Complete Your Profile

Open the `Profile` tab and fill in:

- name
- headline
- location
- education
- experience
- skills
- profile image URL
- bio

You can also configure privacy per field:

- `Public`
- `Connections`
- `Private`

Then click `Save Profile`.

## 3.4 Upload Your Resume

1. Open `Resume Vault`.
2. Choose a PDF or DOCX file.
3. Click `Upload Encrypted Resume`.

What happens next:

- The file is encrypted before storage.
- The system extracts job-matching signals from the uploaded content.
- You will see resume insights such as:
  - parser used
  - word count
  - extracted skills
  - top keywords

## 3.5 Understand Resume Insights

After a successful upload, the Resume Vault may show:

- extracted skills like `React`, `Node.js`, `AWS`
- top keywords identified from the document
- whether parsing succeeded
- any parsing warning if text extraction was incomplete

These insights drive the intelligent matching feature in job search.

## 3.6 Search for Jobs

Open `Opportunities` and use filters such as:

- keywords
- company
- location
- skill
- workplace type
- employment type

If you are logged in as a user, the job results are sorted by resume match score.

## 3.7 Read the Match Score

When intelligent matching is available, a job card may show:

- score percentage
- fit band: `Strong`, `Good`, `Potential`, or `Low`
- matched skills
- missing signals
- keyword overlap

How to use it:

- Prioritize higher match scores first.
- Read the missing skills list before applying.
- Improve your profile or resume if the same missing skills appear repeatedly.

## 3.8 Apply for a Job

1. In `Opportunities`, click `Apply` on a job card.
2. Enter a short cover note.
3. Click `Submit Application`.

Requirements:

- You must have an uploaded resume before applying.
- You can only apply once per job.

## 3.9 Track Your Applications

In the `My Applications` section, you can review:

- company and job title
- current application status
- shortlist state
- status history
- role-fit score for the application when available

Possible statuses:

- `Applied`
- `Reviewed`
- `Interviewed`
- `Rejected`
- `Offer`

## 3.10 Configure Encrypted Messaging

Open `Messages`.

If messaging is not set up yet:

1. Enter a messaging passphrase.
2. Confirm it.
3. Click `Generate Messaging Keys`.

This creates:

- a public key stored on the server
- an encrypted private key bundle protected by your passphrase

## 3.11 Unlock Messaging

To read or send encrypted messages:

1. Open `Messages`.
2. Enter your messaging passphrase.
3. Click `Unlock Conversations`.

If the passphrase is correct, your private messaging key becomes available for that browser session.

## 3.12 Start or Use a Secure Conversation

1. Select available contacts.
2. Start a direct or group conversation.
3. Type a message.
4. Click `Send Encrypted Message`.

Important:

- The server stores ciphertext only for these chats.
- You must unlock messaging each session to decrypt message history.

## 3.13 Download Your Resume Securely

1. Open `Resume Vault`.
2. In the authenticator code area, use the on-screen keyboard.
3. Enter the current TOTP.
4. Click `Download Resume`.

Why the on-screen keyboard exists:

- It is part of the secure flow for high-risk actions.
- It reduces reliance on normal keyboard input during sensitive OTP entry.

## 3.14 Reset Your Password

There are two ways to reset a password:

### While logged in

1. Open `Security`.
2. Use the on-screen keyboard to enter the current TOTP.
3. Enter the new password.
4. Confirm the new password.
5. Click `Confirm Password Reset`.

### From the login page

1. Click `Forgot Password`.
2. Provide your email or phone.
3. Continue to the confirm step.
4. Use the on-screen keyboard to enter the current TOTP.
5. Enter and confirm the new password.
6. Submit the reset form.

## 3.15 Delete Your Account

1. Open `Security`.
2. In the `Delete Account` section, enter the TOTP using the on-screen keyboard.
3. Click `Delete My Account`.

Warning:

- This is permanent.
- Your account, access, and related data references will be removed from active records.

## 4. Recruiter Guide

## 4.1 Register as a Recruiter

At registration, choose role = `recruiter`.

Then complete login and TOTP setup the same way as a normal user.

## 4.2 Create a Company Page

1. Open `Hiring`.
2. In `Company Manager`, enter:
   - company name
   - description
   - location
   - website
3. Click `Create Company`.

The company will appear in your managed company list.

## 4.3 Edit a Company

1. In the company list, click `Manage`.
2. Update the form fields.
3. Click `Save Company`.

## 4.4 Create a Job Posting

1. Select a company in the recruiter workspace.
2. Fill in:
   - job title
   - location
   - description
   - required skills
   - workplace type
   - employment type
   - salary range if desired
   - application deadline
   - status
3. Click `Post Job`.

## 4.5 Edit a Job Posting

1. In the job list, click `Edit Job`.
2. Modify the fields.
3. Click `Save Job`.

## 4.6 Review Applicants

When candidates apply, the recruiter view shows:

- applicant identity
- cover note
- resume file name
- current application status
- intelligent match score
- matched skills
- missing signals
- keyword overlap

This allows recruiters to prioritize stronger candidates quickly while still reviewing all applications fairly.

## 4.7 Update Applicant Status

For each applicant:

1. Change the status from the dropdown.
2. Mark `Shortlisted` if appropriate.
3. Add a recruiter note if needed.
4. Click `Save Review`.

All important changes are written to the secure audit log.

## 4.8 Secure Messaging with Candidates

Recruiters can use the same encrypted messaging workflow as job seekers:

1. Configure messaging identity if not already done.
2. Unlock messaging for the session.
3. Start or continue a conversation with a candidate.

## 5. Platform Admin Guide

## 5.1 Access the Admin Dashboard

Admins see an `Admin` tab after login.

The dashboard includes:

- user totals
- recruiter count
- suspended accounts
- uploaded resume count
- company and job totals
- application totals
- conversation and message totals
- audit integrity status
- blockchain audit summary
- recent audit logs

## 5.2 Read Audit Integrity

The dashboard displays:

- whether the audit chain is valid
- chain version
- blockchain version
- broken index if integrity fails
- current block difficulty
- whether proof-of-work is enabled
- latest block hash

If the integrity panel shows `FAILED`, treat it as a serious issue and investigate immediately.

## 5.3 Suspend a User

1. Open the admin user table.
2. Find the user.
3. Click `Suspend`.

Effects:

- The user can no longer continue protected actions.
- Future protected requests are denied.
- The action is logged securely.

## 5.4 Reactivate a User

1. Find the suspended account.
2. Click `Activate`.

This action is also audited.

## 5.5 Delete a User

1. Find the user.
2. Click `Delete`.

This removes:

- the user account
- related messaging membership references
- application ownership records
- stored resume ciphertext if present

Admins cannot suspend or delete themselves from the dashboard.

## 6. Troubleshooting

## 6.1 I cannot log in

Check:

- identifier is correct
- password is correct
- authenticator app code is current
- account is not suspended

## 6.2 My authenticator code is rejected

Possible causes:

- phone time is out of sync
- wrong account selected in the authenticator app
- old code expired

Try:

- waiting for a new 6-digit code
- checking device time sync

## 6.3 My resume uploaded but no skills were extracted

Possible reasons:

- the PDF or DOCX contains limited machine-readable text
- the document is image-heavy or poorly structured

The resume is still stored securely, but matching quality may be lower. Try uploading a cleaner text-based PDF or DOCX.

## 6.4 Messaging will not unlock

Possible reasons:

- incorrect passphrase
- browser session changed

Remember:

- the messaging passphrase is not the same as the login password
- the private key is encrypted with the messaging passphrase you created during setup

## 6.5 I cannot download my resume

Check:

- you uploaded a resume
- your TOTP is current
- your session is still valid

## 6.6 Recruiter cannot see a candidate resume

The recruiter must be:

- the owner/admin of the relevant company, and
- authorized through application flow or granted access

## 7. Best Practices

- Use a strong password and store it safely.
- Protect the authenticator app on your device.
- Upload text-readable resumes for better matching.
- Review missing skills before applying to a role.
- Use encrypted messaging only after unlocking your private key bundle.
- For demos, prepare one user account, one recruiter account, and one admin account in advance.

## 8. Quick Demo Checklist

### Job seeker

1. Log in
2. Show profile
3. Upload resume
4. Show extracted skills
5. Search jobs
6. Show match score
7. Apply
8. Show application status
9. Demonstrate secure message or secure resume download

### Recruiter

1. Log in
2. Create company
3. Create job
4. Show applicant list
5. Show intelligent match score
6. Update status and note

### Admin

1. Open dashboard
2. Show integrity status
3. Show blockchain summary
4. Suspend/reactivate a user
5. Show recent audit entries

## 9. Final Reminder

This platform is designed to demonstrate secure workflows, cryptographic protections, audit integrity, and role-aware functionality for the course project. For the strongest demonstration:

- keep authenticator apps ready
- upload a readable sample resume
- create at least one realistic recruiter job posting
- use the admin dashboard to show the audit chain and blockchain bonus clearly
