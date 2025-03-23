# MailCheckPro

A comprehensive FastAPI-based REST API that performs thorough email validation and verification through multiple checks including format validation, domain verification, SMTP checks, and blacklist verification.

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.68.0+-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Features

- ✅ Strict email format validation
  - RFC 5322 compliant
  - Checks for consecutive dots
  - Length restrictions
  - Character validation
  - Local part and domain rules

- 🔍 Domain verification
  - MX record checking
  - Domain existence verification
  - DNS record validation

- 📧 SMTP verification
  - Mailbox existence check
  - Catch-all detection
  - Special handling for major email providers
  - Enhanced error handling

- 🛡️ Blacklist checking
  - DNS blacklist (DNSBL) verification
  - Known spam domain checking
  - Disposable email detection
  - Multiple blacklist sources

- ⚡ Asynchronous processing
- 🛡️ Comprehensive error handling
- 📝 Interactive Swagger UI documentation

## API Response Format

```json
{
  "email_address": "example@domain.com",
  "syntax_validation": "valid/invalid",
  "domain_check": "exists/doesn't exist",
  "smtp_verification": "mailbox exists/mailbox doesn't exist",
  "blacklisted": true/false,
  "activity": "active/inactive/unknown",
  "result": "deliverable/undeliverable",
  "status": "valid/invalid",
  "details": "Detailed verification message"
}
```

## Prerequisites

- Python 3.9 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/MailCheckPro.git
cd MailCheckPro
```

2. Create and activate a virtual environment:

```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the Application

### Local Development
```bash
uvicorn app:app --reload
```
The API will be available at `http://localhost:8000`

### Using Docker
```bash
# Build the Docker image
docker build -t mailcheckpro .

# Run the container
docker run -p 8000:8000 mailcheckpro
```

## API Documentation

Once the application is running, you can access:
- Interactive Swagger UI documentation: `http://localhost:8000/docs`
- ReDoc documentation: `http://localhost:8000/redoc`

## Validation Steps

1. **Syntax Validation**
   - Checks email format against RFC 5322 rules
   - Validates length restrictions
   - Checks for invalid characters
   - Prevents consecutive dots
   - Validates local part and domain rules

2. **Domain Check**
   - Verifies domain existence
   - Checks MX records
   - Validates DNS configuration

3. **SMTP Verification**
   - Attempts to verify mailbox existence
   - Special handling for major email providers
   - Catch-all detection
   - Enhanced error handling

4. **Blacklist Check**
   - Checks against DNS blacklists
   - Verifies against known spam domains
   - Checks disposable email domains
   - Multiple blacklist source verification

## Response Examples

1. **Valid Email**
```json
{
  "email_address": "user@example.com",
  "syntax_validation": "valid",
  "domain_check": "exists",
  "smtp_verification": "mailbox exists",
  "blacklisted": false,
  "activity": "active",
  "result": "deliverable",
  "status": "valid",
  "details": "Email verification complete"
}
```

2. **Invalid Format**
```json
{
  "email_address": "invalid..email@domain.com",
  "syntax_validation": "invalid",
  "domain_check": "unknown",
  "smtp_verification": "unknown",
  "blacklisted": false,
  "activity": "unknown",
  "result": "undeliverable",
  "status": "invalid",
  "details": "Invalid email format"
}
```

3. **Blacklisted Domain**
```json
{
  "email_address": "user@spam.com",
  "syntax_validation": "valid",
  "domain_check": "exists",
  "smtp_verification": "mailbox exists",
  "blacklisted": true,
  "activity": "active",
  "result": "undeliverable",
  "status": "invalid",
  "details": "Domain is blacklisted: Known spam domain"
}
```

## Development Notes

- The SMTP verification might not work for all email providers due to anti-spam measures
- Major email providers (Gmail, Outlook, etc.) have special handling due to their security measures
- Some mail servers might return false positives/negatives
- Consider implementing rate limiting for production use

## Dependencies

- FastAPI
- Uvicorn
- Pydantic
- DNSPython
- Email-validator
- Requests

