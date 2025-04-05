# QMail

**QMail** is an advanced email analytics and security tool designed to monitor, filter, and analyze incoming emails. It integrates with popular email providers such as Gmail using robust authentication (including SSO) and modern threat detection techniques. QMail provides actionable insights into your email activity by identifying scams, phishing attempts, and malicious content—all while ensuring privacy through encryption and secure data handling.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Privacy / Key Features](#privacy--key-features)
3. [Architecture & Technical Stack](#architecture--technical-stack)
4. [Usage](#usage)
5. [API Endpoints & Integration](#api-endpoints--integration)
6. [Deployment & Maintenance](#deployment--maintenance)
7. [Future Enhancements](#future-enhancements)

---

## 1. Project Overview

QMail is an advanced email analytics and security tool designed to:

- Monitor and filter incoming emails.
- Analyze emails in real time to identify scams, phishing, and other threats.
- Leverage robust authentication (including SSO) and modern threat detection techniques.
- Ensure privacy through encryption and secure data handling.

---

## 2. Privacy / Key Features

### Optional AI Features
- **Optional AI Button:**  
  Users can toggle an AI-powered filter on or off. When activated, advanced AI techniques (e.g., integration with OpenAI) analyze emails to detect scams, phishing attempts, and suspicious content.
  
- **AI Agent Unsubscriber:**  
  Automatically accesses emails and interacts with websites on your behalf to manage subscriptions. It processes personal data (like email content, login credentials, and site activity) solely to perform unsubscribe actions without long-term data storage.

- **Deep Safety Check:**  
  Analyzes emails in-depth—scanning sender information, URLs, and message content—to detect phishing and other threats. Users can revoke AI access at any time.

### Sender Domain Analysis
- **Domain Extraction:**  
  Parses email addresses to extract domains (e.g., extracting “gmail.com” from “user@gmail.com”).
- **Trust Verification:**  
  Compares the extracted domain against a predefined list of trusted domains, including major email providers (Gmail, Outlook, Yahoo, ProtonMail), educational institutions (.edu), government organizations (.gov), and well-known companies (Microsoft, Apple, Google).
- **TLD Analysis:**  
  Evaluates top-level domains (TLDs) and flags suspicious ones (such as .xyz, .top, .loan, .club, .work).

### Text Content Analysis
- **Suspicious Keywords & Phrases:**  
  Detects over 50 phishing-related keywords (e.g., “urgent”, “immediate action”, “account suspended”, “verify your account”, “click here”).
- **Regex Pattern Matching:**  
  Uses advanced regular expressions to identify sophisticated phishing language (e.g., patterns matching “urgent.*action”, “verify.*account”).
- **Urgency & Financial Hooks:**  
  Flags language that creates artificial time pressure, as well as content that mentions money, prizes, investments, or lottery winnings.
- **Action Prompts:**  
  Recognizes calls to action like “click here” or “log in now.”

### URL Analysis
- **URL Extraction:**  
  Extracts all URLs from the email body and subject using regex.
- **IP Address & Typo Detection:**  
  Flags URLs that use IP addresses or show signs of typosquatting (e.g., “paypa1.com” instead of “paypal.com”).
- **Excessive Subdomains & Redirects:**  
  Identifies URLs with many subdomains or those using login redirects—a common phishing technique.

### Risk Scoring System
- **Weighted Scoring:**  
  Each risk factor is assigned a weight:
  - Untrusted domain: +30 points
  - Suspicious keywords: +5 points each (max 30)
  - Suspicious patterns: +10 points each (max 40)
  - Suspicious URLs: +15 points each (max 50)
  - Grammatical errors: +20 points
- **Risk Calculation:**  
  The total risk score is converted into a 0–10 security scale.
- **Risk Level Classification:**
  - **Secure:** 8–10
  - **Cautious:** 5–7.9
  - **Unsafe:** 2–4.9
  - **Dangerous:** Below 2

### Recommendation Generation
- **Customized Advice:**  
  Generates specific recommendations based on the risk level and identified issues.
- **Actionable Guidance:**  
  Provides clear steps, such as avoiding clicks on suspicious links, reporting phishing attempts, or changing passwords if necessary.

### Error Handling & Graceful Degradation
- **Robust Error Handling:**  
  Catches and logs exceptions during analysis.
- **Fallback Analysis:**  
  Offers a basic security assessment even if detailed checks fail.
- **Detailed Explanations:**  
  Clearly explains why an email is flagged as suspicious.

---

## 3. Architecture & Technical Stack

- **Frontend:**  
  Built as a Progressive Web App (PWA) using Python and React on Replit for an elegant, minimalist, and user-friendly dashboard.
  
- **Backend:**  
  Developed using Node.js (Express) or Python (Flask/FastAPI) to provide RESTful API endpoints that handle:
  - Authentication (via Replit’s built‑in OAuth for SSO)
  - Email analysis
  - Encryption
  - AI integration

- **Database:**  
  Utilizes Replit’s built‑in database to store user settings, email data, and analysis logs.

- **Third-Party Integrations:**  
  - **OpenAI API:** For scam detection and email content analysis.
  - **Azure Quantum:** For generating quantum-enhanced random numbers to improve encryption.
  - **Gmail API:** For real-time email fetching and processing.

---

## 4. Usage

- **Authentication:**  
  Users sign in via Replit’s built‑in OAuth, enabling secure SSO across multiple email providers.
  
- **Email Analysis:**  
  The system fetches live emails and processes them through an analysis engine that scores each email on a 0–10 trust scale.
  
- **Dashboard Interaction:**  
  The user-friendly dashboard displays email metrics, filtering statuses, and real-time alerts. Users can also configure custom filtering rules and review historical scam alerts.
  
- **Unsubscribe Automation:**  
  AI agents monitor incoming emails for subscription content and generate automatic unsubscribe requests, streamlining inbox management.

---

## 5. API Endpoints & Integration

- **Authentication Endpoint:**  
  - **URL:** `/api/auth`  
  - **Method:** POST  
  - **Description:** Handles user sign-in and token generation via OAuth.

- **Email Analysis Endpoint:**  
  - **URL:** `/api/analyze-email`  
  - **Method:** POST  
  - **Description:** Accepts raw email data and returns a trust score (0–10), risk label, and a detailed list of issues.

- **Unsubscribe Endpoint:**  
  - **URL:** `/api/unsubscribe`  
  - **Method:** POST  
  - **Description:** Processes unsubscribe requests using AI-driven logic.

- **Encryption Endpoint:**  
  - **URL:** `/api/encrypt-email`  
  - **Method:** POST  
  - **Description:** Encrypts outgoing email content and manages key generation using Azure Quantum.

---

## 6. Deployment & Maintenance

- **Deployment:**  
  The application is deployed using Replit’s built‑in deployment features. Continuous integration ensures that updates are tested and deployed seamlessly.

- **Monitoring:**  
  Logging and monitoring are implemented for both backend and frontend components. Performance and error rates are tracked using appropriate tools.

- **Maintenance:**  
  Regular code commits, updates, and documentation revisions ensure the project remains up-to-date with current security standards and feature requirements.

- **Tech Stack Enhancements:**  
  Utilizes LLMs like LLaMA or TinyLLaMA (fine-tuned for scam detection) and integrates tools such as Ollama, HuggingFace, Transformers, or ONNX Runtime.

---

## 7. Future Enhancements

- **Advanced AI Integration:**  
  Future iterations may expand the AI engine to deliver even more precise scam detection and filtering capabilities.

- **Enhanced Unsubscribe Automation:**  
  Further refinement of AI agents to handle more complex unsubscribe workflows, including autofill of credentials on trusted sites.

- **Enhanced User Customization:**  
  Allow users to create and adjust custom filtering rules, whitelist/block specific domains, and set personalized risk thresholds.

- **Outbound Email Encryption / Azure Quantum:**  
  Leverage future quantum computing advancements for improved encryption and reduced processing times.

---

*QMail is designed to be both powerful and user-friendly, ensuring that users have full control over their email
