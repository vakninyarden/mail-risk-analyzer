# Mail Risk Analyzer

Mail Risk Analyzer is a Gmail Add-on that analyzes the currently opened email and shows the user a risk score, a clear verdict, and a short explanation of why the email was marked as safe, suspicious, or high risk.

---

## What the System Does

When the user opens an email in Gmail and runs the add-on, the add-on reads the details of the currently opened message and sends them to the backend.

The backend analyzes the email using a set of rules, calculates a risk score, and returns a response with the following structure:

* `score` - a score between 0 and 100
* `verdict` - for example `Likely Safe`, `Suspicious`, or `High Risk`
* `reasons` - short and clear explanations for the decision

Example response:

```json
{
  "score": 85,
  "verdict": "High Risk",
  "reasons": [
    "The email asks the user to verify account information.",
    "The sender domain looks similar to a known brand domain.",
    "The email contains a shortened URL."
  ]
}
```

---

## Architecture Overview

The system is split into two main parts:

```text
Gmail Add-on  →  Python Backend
```

### Gmail Add-on

The Gmail Add-on is the part the user interacts with inside Gmail.

It is responsible for:

* Reading the currently opened email
* Extracting the `subject`, `sender`, and `body`
* Sending the data to the backend
* Displaying the result inside Gmail

The add-on does not perform the risk analysis itself. It acts as the UI layer and as the connection between Gmail and the backend service.

### Python Backend

The backend is built with FastAPI.

It is responsible for:

* Receiving the email data from the add-on
* Building a structured context from the received data
* Running a rule-based engine to detect suspicious signals
* Calculating the `score` and `verdict`
* Returning clear explanations to the user

---

## Project Structure

```text
mail-risk-analyzer/
│
├── addon/
│   ├── Code.gs
│   └── appsscript.json
│
├── backend/
│   ├── main.py
│   ├── requirements.txt
│   │
│   └── analysis/
│       ├── context_builder.py
│       ├── engine.py
│       ├── models.py
│       │
│       └── rules/
│           ├── base.py
│           ├── content_rules.py
│           ├── sender_rules.py
│           └── url_rules.py
│
├── README.md
└── .gitignore
```

---

## Backend Design

The backend is built around a generic rule-based engine.

Each check is represented by an independent Rule. Every Rule receives the same `EmailContext`, checks for a specific signal, and returns a list of `Findings`.

Examples of things rules can check:

* Urgent language such as `urgent` or `action required`
* Requests to log in, enter a password, or verify an account
* Shortened URLs
* URLs that use HTTP instead of HTTPS
* Sender domains that look similar to known brands
* A mismatch between the display name and the real sender domain
* Punycode or suspicious characters in a domain

This structure makes the system easy to extend. To add a new check, I can add a new Rule without changing the whole engine.

---

## EmailContext

Before the rules run, the system builds an object called `EmailContext`.

This object contains prepared data for analysis, such as:

* `subject`
* `sender`
* `body`
* `full_text`
* extracted URLs
* sender email
* sender domain
* display name

This way, each Rule receives clean and structured data and does not need to repeat parsing logic on its own.

---

## Detection Rules

Every Rule in the system implements a basic interface called `DetectionRule`.

Each Rule returns one or more `Finding` objects.

Each `Finding` includes:

* rule id
* title
* description
* severity
* confidence
* score impact
* evidence
* whether it is a hard signal

This allows the system to calculate the score in a structured way and also return clear explanations to the user.

---

## Scoring Logic

The final score is calculated from all the Findings returned by the rules.

Each Finding adds a certain number of points to the final score.

Examples:

* A URL shortener adds a low-to-medium score impact
* An HTTP link adds a low score impact
* A login or password request adds a higher score impact
* Brand impersonation or a lookalike domain adds a high score impact
* Punycode or a Unicode domain is treated as a strong signal

The engine also takes combinations of signals into account.

For example:

* Credential request + suspicious URL → significantly increases the score
* Brand impersonation + account verification request → high risk
* Lookalike domain → high risk even without many suspicious keywords
* Urgent language + password request → at least `Suspicious`

The verdict is based on the score:

```text
0–39    Likely Safe
40–74   Suspicious
75–100  High Risk
```

I chose to use `High Risk` instead of `Malicious`, because the system cannot know with complete certainty that an email is malicious. It can say that the email has a high risk based on the signals that were found.

---

## Security Considerations

Security was a central part of the project design.

The system treats all email data as untrusted input:

* subject
* sender
* body
* URLs
* attachments in a future version
* external service responses in a future version

Security decisions made in this project:

* The system does not open URLs
* The system does not send requests to URLs found in the email
* The system does not download content from links
* The system does not execute any content from the email
* The email body is truncated to a maximum length before analysis
* URLs are analyzed as strings only
* Email content is not stored in a database
* The backend processes the data in memory and returns a response

For example, if a URL contains a pattern that looks like SQL Injection, the system does not try to run it or open it. It only marks it as a suspicious signal.

---

## Implemented Rule Categories

### Content Rules

Rules that analyze the email content:

* Urgent or pressure-based language
* Requests to log in, enter a password, or verify an account
* Financial language such as invoice, refund, or payment
* Prize, reward, or free gift wording

### URL Rules

Rules that analyze links inside the email:

* URL shorteners
* HTTP instead of HTTPS
* Suspicious words inside URLs, such as login, verify, or payment
* Patterns that look like injection payloads
* Punycode or unusual characters in a domain

### Sender Rules

Rules that analyze the sender:

* Digits inside the sender domain
* A mismatch between the display name and the domain
* Possible brand impersonation
* A lookalike domain that is similar to an official company domain

---

## Testing and Tuning

I tested the system with several types of emails:

* A completely normal email
* A job interview invitation
* A classic PayPal phishing email
* An email with a shortened URL
* An email with only an HTTP link
* An email with a URL that looks like SQL Injection
* An email with a punycode domain
* An email that promises a prize or free gift
* An email that mentions Microsoft/Facebook only inside the body

During testing, I found a false positive: a legitimate interview email was marked as `High Risk` because it mentioned Microsoft Teams and Facebook in the email body.

After that, I changed the rules so Brand Impersonation is not based on every brand mention in the body. Instead, it focuses on stronger identity signals such as the display name, subject, and sender domain.

I also tuned the scoring so weak signals like HTTP or a URL shortener do not cause `High Risk` by themselves.

---

## Running the Backend

From the `backend` directory:

```bash
pip install -r requirements.txt
```

On Windows, if `pip` is not recognized:

```bash
py -m pip install -r requirements.txt
```

Run the server:

```bash
py -m uvicorn main:app --reload
```

The backend will run locally at:

```text
http://127.0.0.1:8000
```

Health check:

```text
http://127.0.0.1:8000/health
```

Swagger UI:

```text
http://127.0.0.1:8000/docs
```

---

## Connecting the Add-on to the Local Backend

Google Apps Script cannot call `localhost` directly, so I used ngrok to expose the local FastAPI backend through a temporary public URL.

Run ngrok:

```bash
ngrok http 8000
```

After receiving the public ngrok URL, update this value in `addon/Code.gs`:

```javascript
const BACKEND_BASE_URL = "https://your-ngrok-url";
```

Do not add `/health` at the end of the URL. The add-on code appends `/analyze-email` by itself.

---

## Gmail Add-on Setup

The Gmail Add-on is built with Google Apps Script.

The relevant files are located under:

```text
addon/
├── Code.gs
└── appsscript.json
```

To test the add-on:

1. Create a Google Apps Script project.
2. Copy the content of `addon/Code.gs` into the Apps Script editor.
3. Copy the content of `addon/appsscript.json` into the manifest file.
4. Create a test deployment for the Google Workspace Add-on.
5. Install the test deployment for the current user.
6. Open Gmail, refresh the page, open an email, and click the Mail Risk Analyzer add-on.

---

## Limitations

The project is an MVP and not a production-ready security product.

Current limitations:

* No attachment analysis yet
* No SPF / DKIM / DMARC checks yet
* No VirusTotal 
* No sender history database
* The known organization list is limited
* No active AI model integration at this stage
* ngrok is used for local development and demo only, not production

---

## Future Improvements

Things I would add with more time:

* SPF, DKIM and DMARC checks from email headers
* Domain, URL and IP reputation checks
* VirusTotal or Google Safe Browsing integration
* Attachment metadata and file hash analysis
* Privacy-aware sender history
* Detection of a sender the user has never communicated with before
* Detection of employee impersonation inside an organization
* A larger and configurable known-organization registry
* Optional AI-based analysis as another rule in the engine
* Deploying the backend to a cloud environment instead of ngrok
* Improving the Gmail UI

---

## AI Analysis - Future Feature

The system is designed so an AI-based rule can be added later.

The AI would not replace the rule engine and would not decide the final verdict by itself. It would be another signal inside the engine.

In a future implementation, the AI rule would receive a sanitized and truncated email preview, return JSON in a strict schema, and the backend would validate the response before using it.

The AI response would also be treated as untrusted external input.

---

## Summary

This project implements a working Gmail Add-on connected to a Python FastAPI backend that analyzes emails using a generic rule-based risk engine.

The main focus was to build a solution that is clear, explainable, security-aware, and easy to extend.

The system does not return only a score. It also returns the reasons behind the decision, so the user can understand why an email was flagged as suspicious or high risk.
