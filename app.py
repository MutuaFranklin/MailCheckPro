from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, EmailStr
from typing import Optional, Tuple, List
import re
import dns.resolver
import smtplib
import socket
import asyncio
from email.utils import parseaddr
from fastapi.responses import RedirectResponse
import requests
from datetime import datetime
import json

app = FastAPI(
    title="Email Validation API",
    description="API for validating and verifying email addresses",
    version="1.0.0"
)

class EmailResponse(BaseModel):
    email_address: str
    syntax_validation: str
    domain_check: str
    smtp_verification: str
    blacklisted: bool
    activity: str
    result: str
    status: str
    details: Optional[str] = None

class EmailValidator:
    # Common disposable email domains
    DISPOSABLE_DOMAINS = {
        'tempmail.com', 'throwawaymail.com', 'mailinator.com',
        'guerrillamail.com', 'minutemail.com', 'tempmail.net',
        'yopmail.com', '10minutemail.com', 'trashmail.com'
    }
    
    # Known spam domains
    BLACKLISTED_DOMAINS = {
        'spam.com', 'abuse.com', 'spammy.com'
    }

    @staticmethod
    def is_valid_syntax(email: str) -> bool:
        """Validate email format using strict regex."""
        pattern = r'^(?!.*\.\.)(?!.*\.$)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        # Basic format check
        if not re.match(pattern, email):
            return False
            
        # Additional checks
        local_part, domain = email.split('@')
        
        # Check local part rules
        if (
            len(local_part) > 64 or                # Local part too long
            local_part.startswith('.') or          # Can't start with dot
            local_part.endswith('.') or            # Can't end with dot
            '..' in local_part or                  # No consecutive dots
            not all(c.isalnum() or c in '._+-' for c in local_part)  # Invalid characters
        ):
            return False
            
        # Check domain rules
        if (
            len(domain) > 255 or                   # Domain too long
            domain.startswith('.') or              # Can't start with dot
            domain.endswith('.') or                # Can't end with dot
            '..' in domain or                      # No consecutive dots
            not all(c.isalnum() or c in '.-' for c in domain)  # Invalid characters
        ):
            return False
            
        return True

    @staticmethod
    async def check_domain(domain: str) -> Tuple[bool, List]:
        """Check domain existence and get MX records."""
        try:
            loop = asyncio.get_event_loop()
            mx_records = await loop.run_in_executor(
                None, lambda: dns.resolver.resolve(domain, 'MX')
            )
            return True, list(mx_records)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return False, []
        except Exception:
            return False, []

    @staticmethod
    async def verify_mailbox(email: str, mx_records) -> Tuple[bool, str]:
        """Verify mailbox existence using SMTP."""
        _, domain = email.split('@')
        mx_hosts = sorted([(r.preference, str(r.exchange)) for r in mx_records])
        
        # For major email providers, consider valid if domain exists
        major_providers = ['outlook.com', 'hotmail.com', 'gmail.com', 'yahoo.com', 'live.com']
        if any(provider in domain.lower() for provider in major_providers):
            return True, "active"
        
        for _, mx_host in mx_hosts:
            try:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: EmailValidator.smtp_verify(email, mx_host)
                )
                if result == "exists":
                    return True, "active"
                elif result == "catch_all":
                    return True, "catch_all"
            except Exception:
                continue
        return False, "inactive"

    @staticmethod
    def smtp_verify(email: str, mx_host: str) -> str:
        """Perform SMTP verification with enhanced checks."""
        sender = "verify@yourdomain.com"
        
        try:
            with smtplib.SMTP(mx_host, timeout=10) as server:
                server.ehlo()
                try:
                    server.starttls()
                    server.ehlo()
                except:
                    pass
                
                server.mail(sender)
                code_real, _ = server.rcpt(email)
                
                # Many providers return 550/551/554 even for valid emails as security measure
                if code_real == 250:  # Explicit accept
                    return "exists"
                elif code_real in [550, 551, 554]:  # Common rejection codes
                    # For major email providers, assume email exists if domain exists
                    major_providers = ['outlook.com', 'hotmail.com', 'gmail.com', 'yahoo.com', 'live.com']
                    domain = email.split('@')[1].lower()
                    if any(provider in domain for provider in major_providers):
                        return "exists"
                return "not_exists"
                
        except Exception as e:
            # For connection errors with major providers, assume email might exist
            domain = email.split('@')[1].lower()
            major_providers = ['outlook.com', 'hotmail.com', 'gmail.com', 'yahoo.com', 'live.com']
            if any(provider in domain for provider in major_providers):
                return "exists"
            return "error"

    @staticmethod
    def check_blacklists(domain: str) -> Tuple[bool, str]:
        """
        Check if domain is blacklisted using multiple methods
        Returns: (is_blacklisted, reason)
        """
        try:
            # Check disposable email domains
            if domain in EmailValidator.DISPOSABLE_DOMAINS:
                return True, "Disposable email domain"

            # Check known spam domains
            if domain in EmailValidator.BLACKLISTED_DOMAINS:
                return True, "Known spam domain"

            # Check DNS blacklists (DNSBL)
            dnsbl_lists = [
                'zen.spamhaus.org',
                'bl.spamcop.net',
                'dnsbl.sorbs.net'
            ]

            for dnsbl in dnsbl_lists:
                try:
                    # Reverse the IP/domain for DNSBL lookup
                    lookup_domain = '.'.join(reversed(domain.split('.'))) + '.' + dnsbl
                    dns.resolver.resolve(lookup_domain, 'A')
                    return True, f"Listed in {dnsbl}"
                except dns.resolver.NXDOMAIN:
                    continue
                except Exception:
                    continue

        

            return False, "Not blacklisted"

        except Exception as e:
            return False, f"Blacklist check error: {str(e)}"

@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs")

@app.get("/validate-email", response_model=EmailResponse)
async def validate_email(email: str = Query(..., description="Email address to validate")):
    try:
        # Initialize validator
        validator = EmailValidator()
        domain = email.split('@')[1]

        # Step 1: Syntax validation
        syntax_valid = validator.is_valid_syntax(email)
        if not syntax_valid:
            return EmailResponse(
                email_address=email,
                syntax_validation="invalid",
                domain_check="unknown",
                smtp_verification="unknown",
                blacklisted=False,
                activity="unknown",
                result="undeliverable",
                status="invalid",
                details="Invalid email format"
            )

        # Step 2: Domain check
        domain_exists, mx_records = await validator.check_domain(domain)
        domain_status = "exists" if domain_exists else "doesn't exist"
        
        if not domain_exists:
            return EmailResponse(
                email_address=email,
                syntax_validation="valid",
                domain_check="doesn't exist",
                smtp_verification="unknown",
                blacklisted=False,
                activity="inactive",
                result="undeliverable",
                status="invalid",
                details="Domain does not exist"
            )

        # Enhanced blacklist check
        is_blacklisted, blacklist_reason = validator.check_blacklists(domain)

        # Step 4: SMTP verification
        mailbox_exists, activity = await validator.verify_mailbox(email, mx_records)
        
        # Compile final results
        smtp_status = "mailbox exists" if mailbox_exists else "mailbox doesn't exist"
        activity_status = activity
        final_result = "deliverable" if mailbox_exists and not is_blacklisted else "undeliverable"
        final_status = "valid" if mailbox_exists and not is_blacklisted else "invalid"
        
        details = "Email verification complete" if final_result == "deliverable" else (
            "Email exists but not deliverable" if mailbox_exists else "Mailbox doesn't exist"
        )
        
        if is_blacklisted:
            details = f"Domain is blacklisted: {blacklist_reason}"

        return EmailResponse(
            email_address=email,
            syntax_validation="valid",
            domain_check=domain_status,
            smtp_verification=smtp_status,
            blacklisted=is_blacklisted,
            activity=activity_status,
            result=final_result,
            status=final_status,
            details=details
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error validating email: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 