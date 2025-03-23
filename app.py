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
    def smtp_verify(email: str, mx_host: str) -> dict:
        """Advanced SMTP verification with institutional domain handling."""
        verification_result = {
            "exists": False,
            "response_code": None,
            "response_message": None,
            "error": None,
            "details": None
        }

        # Institutional domains require special handling
        institutional_domains = {
            'un.org': {
                'mx_pattern': 'protection.outlook.com',
                'requires_tls': True,
                'port': 25,
                'valid_senders': ['postmaster@un.org', 'verify@un.org']
            },
            # Add other institutional domains as needed
        }

        try:
            domain = email.split('@')[1].lower()
            is_institutional = any(domain.endswith(d) for d in institutional_domains.keys())
            domain_config = next((conf for d, conf in institutional_domains.items() 
                                if domain.endswith(d)), None)

            with smtplib.SMTP(mx_host, port=25, timeout=30) as server:
                server.set_debuglevel(1)  # Enable debugging
                
                # Initial connection
                server.ehlo()
                
                # Always try TLS for institutional domains
                if domain_config and domain_config['requires_tls']:
                    server.starttls()
                    server.ehlo()

                # Use domain-specific senders for institutional domains
                sender_addresses = (
                    domain_config['valid_senders'] if domain_config 
                    else ["verify@example.com", "check@example.com"]
                )

                for sender in sender_addresses:
                    try:
                        server.rset()  # Reset connection state
                        from_code = server.mail(sender)
                        
                        # RCPT TO
                        code_to, message = server.rcpt(email)
                        message = str(message).lower()
                        verification_result["response_code"] = code_to
                        verification_result["response_message"] = message

                        # Success case
                        if code_to == 250:
                            verification_result["exists"] = True
                            verification_result["details"] = "Mailbox exists"
                            return verification_result

                        # Handle Exchange Online Protection responses
                        if "protection.outlook.com" in mx_host.lower():
                            # For institutional domains using Exchange Online
                            if is_institutional:
                                if code_to in [550, 551, 554]:
                                    if "recipient not found" in message:
                                        verification_result["details"] = "Mailbox doesn't exist"
                                        return verification_result
                                    # If we get here, the rejection might be due to security
                                    verification_result["exists"] = True
                                    verification_result["details"] = "Mailbox likely exists"
                                    return verification_result

                        # For non-institutional domains, standard verification
                        if code_to in [550, 551, 554]:
                            if any(phrase in message for phrase in [
                                "recipient not found",
                                "user unknown",
                                "no such user",
                                "does not exist"
                            ]):
                                verification_result["details"] = "Mailbox doesn't exist"
                                return verification_result

                    except (smtplib.SMTPServerDisconnected, smtplib.SMTPResponseException):
                        continue

                # If we get here with an institutional domain, assume exists
                if is_institutional:
                    verification_result["exists"] = True
                    verification_result["details"] = "Institutional domain - assumed valid"
                    return verification_result

        except Exception as e:
            verification_result["error"] = str(e)
            verification_result["details"] = "Connection error"
            
        return verification_result

    @staticmethod
    async def verify_mailbox(email: str, mx_records) -> Tuple[bool, str]:
        """Advanced mailbox verification with result analysis."""
        _, domain = email.split('@')
        mx_hosts = sorted([(r.preference, str(r.exchange)) for r in mx_records])
        
        verification_attempts = []
        
        for _, mx_host in mx_hosts:
            try:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: EmailValidator.smtp_verify(email, mx_host)
                )
                verification_attempts.append(result)
                
                # If we got a definitive answer
                if result["exists"]:
                    return True, "active"
                elif result["details"] in ["User doesn't exist", "Exchange Online: User doesn't exist"]:
                    return False, "inactive"
                
            except Exception as e:
                print(f"Error with MX host {mx_host}: {str(e)}")
                continue
        
        # Analyze all attempts
        if verification_attempts:
            # Check if any attempt was successful
            if any(attempt["exists"] for attempt in verification_attempts):
                return True, "active"
            
            # Check if we got consistent "user doesn't exist" responses
            if all(
                attempt["details"] in ["User doesn't exist", "Exchange Online: User doesn't exist"]
                for attempt in verification_attempts
                if attempt["details"]
            ):
                return False, "inactive"
        
        # Default response if uncertain
        return False, "inactive"

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