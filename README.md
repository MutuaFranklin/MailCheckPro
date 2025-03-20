# Email Validation and Verification API

A FastAPI-based REST API that validates and verifies email addresses through multiple checks including format validation, domain MX record verification, and SMTP deliverability testing.

## Features

- ✅ Email format validation using regex
- 🔍 Domain MX record verification
- 📧 SMTP deliverability check
- ⚡ Asynchronous processing
- 🛡️ Comprehensive error handling
- 📝 OpenAPI documentation (Swagger UI)

## API Response Format
json
{
"email_address": "example@example.com",
"status": "valid/invalid",
"result": "deliverable/undeliverable",
"details": "Additional information about the verification"
}

## Prerequisites

- Python 3.9 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd email-validator-api
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
docker build -t email-validator-api .

# Run the container
docker run -p 8000:8000 email-validator-api
```

## API Documentation

Once the application is running, you can access:
- Swagger UI documentation: `http://localhost:8000/docs`
- ReDoc documentation: `http://localhost:8000/redoc`

## API Endpoints

### Root Endpoint
- GET `/`
  - Returns a welcome message and basic API information

### Email Validation Endpoint
- GET `/validate-email`
  - Query Parameter: `email` (required)
  - Validates and verifies the provided email address

## Response Status Codes

- `200 OK`: Successful request
- `400 Bad Request`: Invalid input
- `500 Internal Server Error`: Server-side error

## Understanding the Response

The API returns different combinations of status and result:

1. **Invalid Format**
   ```json
   {
     "status": "invalid",
     "result": "undeliverable",
     "details": "Invalid email format"
   }
   ```

2. **No MX Records**
   ```json
   {
     "status": "invalid",
     "result": "undeliverable",
     "details": "Domain does not have MX records"
   }
   ```

3. **Valid but Undeliverable**
   ```json
   {
     "status": "valid",
     "result": "undeliverable",
     "details": "Email exists but is not deliverable"
   }
   ```

4. **Valid and Deliverable**
   ```json
   {
     "status": "valid",
     "result": "deliverable",
     "details": "Email verification complete"
   }
   ```

## Development Notes

- The SMTP verification might not work for all email providers due to anti-spam measures
- In production, use a valid sender email address
- Consider implementing rate limiting for production use
- Some mail servers might return false positives/negatives

## Dependencies

- FastAPI
- Uvicorn
- Pydantic
- DNSPython
- Email-validator

