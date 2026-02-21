# Upwind Student Program — Home Task
## Gmail Add-on: Malicious Email Scorer

---

## Objective

Design and implement a Gmail Add-on that analyzes an opened email and produces a **maliciousness score** with a clear, explainable verdict.

---

## Scope & Expectations

- You may choose which capabilities to implement and which to omit.
- Prioritization, design decisions, and trade-offs are **part of the evaluation**.
- The solution does **not** need to be production-ready.
- The solution should be **deployed in a Gmail account** and demonstrated during the interview.

---

## Capabilities to Consider

### 1. Dynamic Enrichment via External APIs
Fetch reputation and intelligence data dynamically from internet-based APIs.

### 2. Attachment Analysis
Safely analyze email attachments to identify potentially malicious characteristics.

### 3. Email Content and Metadata Analysis
Analyze headers, metadata, and body content to identify suspicious patterns.

### 4. Risk Scoring and Verdict
Combine signals into a single risk score mapped to a clear verdict.

### 5. Explainability
Clearly present why the email received its score and which signals contributed.

### 6. User-Managed Blacklist
Allow users to define personal blacklist entries that influence scoring logic.

### 7. History of Actions
Track previous scans and user actions to provide context and improve decisions.

### 8. Management Console for User Configuration
Provide a simple interface to manage settings, preferences, and policies.

---

## Technical Guidelines

- Gmail Add-on using **Google Workspace APIs**
- Backend service **allowed**
- Focus on **security awareness** and **clean design**

---

## Deliverables

- [ ] Source code
- [ ] Short README describing:
  - Architecture
  - APIs used
  - Implemented features
  - Limitations
