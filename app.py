from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, EmailStr
from typing import Optional
import re
import dns.resolver
import smtplib
import socket
import asyncio
from email.utils import parseaddr

app = FastAPI(
    title="Email Validation API",
    description="API for validating and verifying email addresses",
    version="1.0.0"
)

class EmailResponse(BaseModel):
    email_address: str
    status: str
    result: str
    details: Optional[str] = None

@app.get("/", response_model=dict)
async def root():
    return {"message": "Email Validation API. Use /validate-email endpoint."}

@app.get("/validate-email", response_model=EmailResponse)
async def validate_email(email: str = Query(..., description="Email address to validate")):
    try:
        # Step 1: Validate email format using regex
        if not is_valid_email_format(email):
            return EmailResponse(
                email_address=email,
                status="invalid",
                result="undeliverable",
                details="Invalid email format"
            )
        
        # Step 2: Check if domain has MX record
        domain = email.split('@')[1]
        has_mx = await check_mx_record(domain)
        if not has_mx:
            return EmailResponse(
                email_address=email,
                status="invalid",
                result="undeliverable",
                details="Domain does not have MX records"
            )
        
        # Step 3: Verify email using SMTP
        is_deliverable = await verify_email_smtp(email)
        
        return EmailResponse(
            email_address=email,
            status="valid",
            result="deliverable" if is_deliverable else "undeliverable",
            details="Email verification complete" if is_deliverable else "Email exists but is not deliverable"
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error validating email: {str(e)}")

def is_valid_email_format(email: str) -> bool:
    """Validate email format using regex."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

async def check_mx_record(domain: str) -> bool:
    """Check if domain has MX records."""
    try:
        # Run DNS query in a thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        mx_records = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(domain, 'MX')
        )
        return len(mx_records) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return False
    except Exception:
        return False

async def verify_email_smtp(email: str) -> bool:
    """Verify email deliverability using SMTP."""
    _, domain = email.split('@')
    
    try:
        # Get MX records
        loop = asyncio.get_event_loop()
        mx_records = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(domain, 'MX')
        )
        
        # Sort MX records by preference
        mx_hosts = sorted([(r.preference, str(r.exchange)) for r in mx_records])
        
        if not mx_hosts:
            return False
            
        # Try to connect to the mail server
        for _, mx_host in mx_hosts:
            try:
                # Run SMTP verification in a thread pool
                return await loop.run_in_executor(
                    None, lambda: smtp_verify(email, mx_host)
                )
            except Exception:
                continue
                
        return False
    except Exception:
        return False

def smtp_verify(email: str, mx_host: str) -> bool:
    """Perform SMTP verification."""
    sender = "verify@example.com"  # Use a valid sender email in production
    
    try:
        with smtplib.SMTP(mx_host, timeout=10) as server:
            server.ehlo()
            server.mail(sender)
            code, _ = server.rcpt(email)
            # 250 means success, 550 means no such user
            return code == 250
    except (socket.timeout, smtplib.SMTPException, ConnectionRefusedError):
        return False

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 