---
name: secure-coding
description: Comprehensive OWASP-based security best practices and secure coding standards for Python web application development. Covers OWASP Top 10 vulnerabilities including broken access control (A01), cryptographic failures (A02), injection attacks (A03), insecure design (A04), security misconfiguration (A05), vulnerable components (A06), authentication failures (A07), data integrity failures (A08), logging failures (A09), and SSRF (A10). Includes authentication patterns (MFA, session management, token handling), authorization (RBAC, multi-tenant isolation), input validation, output encoding, secure file handling, secrets management, and defense-in-depth strategies. Provides decision trees, security checklists, Python code examples showing secure and vulnerable patterns, and testing methodologies. Essential for preventing injection attacks, broken authentication, sensitive data exposure, XXE, broken access control, security misconfigurations, XSS, insecure deserialization, and insufficient logging.

Use when developing Python web applications, REST APIs, or backend services requiring security hardening.
---

# Secure Coding Practices for Python Web Applications

This skill provides OWASP-based security guidance for developing secure Python web applications. Use the decision trees below to quickly navigate to relevant guidance.

*OWASP Top 10 Coverage:*
- *A01: Broken Access Control* 
- *A02: Cryptographic Failures*
- *A03: Injection* - Covered throughout (SQL, Command, LDAP injection prevention)
- *A04: Insecure Design* - Security architecture patterns
- *A05: Security Misconfiguration* - Configuration best practices
- *A07: Authentication Failures* - See authentication.md
- *A08: Data Integrity Failures* - Secure deserialization, validation
- *A09: Logging Failures* - Audit logging guidelines
- *A10: SSRF* - Server-Side Request Forgery prevention

## Quick Decision Trees

### Creating a New API Endpoint?


New API Endpoint
├├ Is it unauthenticated? (OWASP A07: Authentication Failures)
├  ├├ YES ├ ├ ï¸ STOP: Review with security team first
├  ├         - Document as public endpoint
├  ├         - Implement rate limiting (prevent brute force)
├  ├         - Validate all inputs (prevent injection - OWASP A03)
├  ├         - See: reference/authentication.md#unauthenticated-apis
├  ├
├  ├├ NO ├ Implement authentication & authorization
├      ├├ Verify session/token is valid and not expired
├      ├├ Extract authenticated user context
├      ├├ Verify user has permission for this resource
├      ├├ Never trust user-supplied IDs without authorization check
├      ├├ See: reference/authentication.md
├
├├ Does it expose data? (OWASP A01: Broken Access Control)
├  ├├ Return ONLY necessary fields (minimize data exposure)
├  ├├ Filter sensitive fields (SSN, passwords, tokens, PII)
├  ├├ Apply role-based access control (RBAC)
├  ├├ Encode output to prevent XSS (OWASP A03)
├  ├├ See: reference/authorization.md
├
├├ Does it accept user input? (OWASP A03: Injection)
   ├├ Validate and sanitize ALL inputs (allowlist approach)
   ├├ Use parameterized queries (prevent SQL injection)
   ├├ Never use eval(), exec(), or pickle on user input
   ├├ Validate file uploads (type, size, content)
   ├├ See: Input Validation section below


### Handling File Uploads?


File Upload (OWASP A04: Insecure Design + A03: Injection)
├├ Is it a standard file type (PDF, image, CSV, JSON)?
├  ├├ Validate file extension AND MIME type (check both)
├  ├├ Implement strict file size limits
├  ├├ Generate random filenames (prevent path traversal)
├  ├├ Store outside web root
├  ├├ See: reference/file-processing.md
├
├├ Is it XML? (XXE Attack Prevention - OWASP A03)
├  ├├ Use defusedxml library (NOT built-in xml)
├  ├├ Disable external entity processing (XXE)
├  ├├ Disable DTD processing
├  ├├ Never use eval() or exec() on XML content
├  ├├ See: reference/file-processing.md
├
├├ Does it involve untrusted content?
   ├├ Scan for malware before processing
   ├├ Process in sandboxed environment
   ├├ Validate content against allowlist
   ├├ Never execute uploaded files
   ├├ Log all upload attempts with user context


### Exposing New Data Fields? (OWASP A01: Broken Access Control)


New Data Field
├├ What type of field?
├  ├├ Password/Secret ├ Hash with bcrypt/Argon2, never return in API
├  ├├ PII (SSN, DOB) ├ Encrypt at rest, strict access control
├  ├├ Boolean flags (is_admin, is_active) ├ Validate on server, never trust client
├  ├├ Dates (expiry, termination) ├ Server-side only, prevent manipulation
├  ├├ Numeric (price, balance) ├ Validate range, prevent negative values
├  ├├ See: reference/data-security.md
├
├├ Who should have READ access?
├  ├├ Public: Non-sensitive profile data only
├  ├├ Authenticated: User's own data
├  ├├ Admin: Users within their tenant/scope
├  ├├ Super Admin: Cross-tenant with audit logging
├  ├├ See: reference/authorization.md
├
├├ Data Protection Requirements
   ├├ Encrypt sensitive data at rest (OWASP A02)
   ├├ Use HTTPS for data in transit
   ├├ Never log sensitive data (OWASP A09)
   ├├ Implement data retention policies
   ├├ Return minimal data needed (data minimization)


## Critical Security Checklist (OWASP Top 10)

### A01: Broken Access Control

- [ ] Implement deny-by-default access control
- [ ] Never trust client-supplied tenant/org identifiers
- [ ] Verify user authorization for EVERY request
- [ ] Enforce authorization checks server-side, not client-side
- [ ] Disable directory listing, prevent path traversal
- [ ] Log access control failures and alert on repeated failures
- [ ] Test with different user roles and tenants

### A02: Cryptographic Failures

- [ ] Encrypt sensitive data at rest using AES-256
- [ ] Use TLS 1.2+ for all data in transit
- [ ] Hash passwords with bcrypt (cost factor 12+) or Argon2
- [ ] Use cryptographically secure random number generators (secrets module)
- [ ] Never roll your own crypto - use established libraries
- [ ] Implement proper key management (rotate keys, use KMS)
- [ ] No sensitive data in URLs, logs, or error messages

### A03: Injection Attacks

- [ ] Use parameterized queries/ORMs (prevent SQL injection)
- [ ] Validate ALL user input (allowlist approach preferred)
- [ ] Sanitize data for output context (HTML, JavaScript, SQL)
- [ ] Use defusedxml for XML parsing (prevent XXE)
- [ ] Never use eval(), exec(), pickle.loads() on user input
- [ ] Validate and sanitize file uploads
- [ ] Use prepared statements for database queries

### A07: Authentication Failures

- [ ] Implement multi-factor authentication (MFA) for sensitive operations
- [ ] Use secure session management (HTTPOnly, Secure, SameSite cookies)
- [ ] Implement account lockout after failed login attempts
- [ ] Strong password policy (length > complexity)
- [ ] Protect against credential stuffing with rate limiting
- [ ] Never expose session identifiers in URLs
- [ ] Implement secure password recovery (don't expose if user exists)

### A09: Security Logging & Monitoring Failures

- [ ] Log all authentication attempts (success and failure)
- [ ] Log authorization failures
- [ ] Log input validation failures
- [ ] Never log sensitive data (passwords, tokens, PII)
- [ ] Include user context, timestamp, and action in logs
- [ ] Implement alerting for suspicious activities
- [ ] Ensure log integrity (tamper-proof)

## Secure Code Patterns (Python)

### Correct: Authentication & Authorization (OWASP A01, A07)

python
import functools
from typing import Optional

def require_authentication(func):
    """Decorator to require valid authentication"""
    @functools.wraps(func)
    def wrapper(request, *args, **kwargs):
        # Verify session/token is valid
        user = get_authenticated_user(request)
        if not user:
            return {"error": "Authentication required"}, 401
        
        # Attach user to request context
        request.user = user
        return func(request, *args, **kwargs)
    return wrapper

def require_permission(permission_name: str):
    """Decorator to enforce permission checks"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(request, *args, **kwargs):
            if not request.user.has_permission(permission_name):
                return {"error": "Insufficient permissions"}, 403
            return func(request, *args, **kwargs)
        return wrapper
    return decorator

@require_authentication
@require_permission('view_employee')
def get_employee(request, employee_id: str):
    """Secure endpoint with authentication and authorization"""
    user = request.user
    
    # Fetch employee with tenant isolation
    employee = db.get_employee(employee_id, tenant_id=user.tenant_id)
    if not employee:
        return {"error": "Not found"}, 404
    
    # Filter sensitive fields based on user role
    return filter_fields(employee, user.role)


### Correct: Multi-Tenant Isolation (OWASP A01)

python
def get_user_data(request, target_user_id: str):
    """Always extract tenant from authenticated user, never from input"""
    
    # ├ CORRECT: Get tenant from authenticated session
    current_user = get_authenticated_user(request)
    tenant_id = current_user.tenant_id
    
    # Pass tenant to ALL database queries
    user = db.query(
        "SELECT * FROM users WHERE id = %s AND tenant_id = %s",
        (target_user_id, tenant_id)  # Parameterized query + tenant filter
    )
    
    if not user:
        return {"error": "Not found"}, 404
    
    # Verify current user can access target user
    if not has_permission(current_user, user, 'read'):
        return {"error": "Access denied"}, 403
    
    return user


### Correct: Secure File Upload (OWASP A03, A04)

python
import os
import secrets
import mimetypes
from pathlib import Path

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

def secure_file_upload(file_data: bytes, filename: str, user_id: str) -> dict:
    """Secure file upload with validation"""
    
    # Validate file size
    if len(file_data) > MAX_FILE_SIZE:
        raise ValueError("File too large")
    
    # Validate file extension
    ext = Path(filename).suffix.lower().lstrip('.')
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"File type not allowed: {ext}")
    
    # Validate MIME type (check both extension and content)
    mime_type, _ = mimetypes.guess_type(filename)
    if not mime_type or not mime_type.startswith(('image/', 'application/pdf')):
        raise ValueError("Invalid file type")
    
    # Generate random filename to prevent path traversal
    random_name = secrets.token_urlsafe(16)
    safe_filename = f"{random_name}.{ext}"
    
    # Store outside web root with user context
    storage_path = f"/secure/uploads/{user_id}/{safe_filename}"
    
    # Save file securely
    os.makedirs(os.path.dirname(storage_path), exist_ok=True)
    with open(storage_path, 'wb') as f:
        f.write(file_data)
    
    # Log upload with user context
    log_event('file_upload', user_id=user_id, filename=safe_filename)
    
    return {"filename": safe_filename, "path": storage_path}


## Common Anti-Patterns (AVOID)

### ├ WRONG: SQL Injection Vulnerability (OWASP A03)

python
# VULNERABLE TO SQL INJECTION
def vulnerable_search(search_term: str):
    # ├ String concatenation with user input
    query = f"SELECT * FROM users WHERE name = '{search_term}'"
    results = db.execute(query)
    # Attacker can input: ' OR '1'='1
    
# ├ CORRECT: Use parameterized queries
def secure_search(search_term: str):
    query = "SELECT * FROM users WHERE name = %s"
    results = db.execute(query, (search_term,))
    return results


### ├ WRONG: Broken Access Control (OWASP A01)

python
# VULNERABLE - Trusts user-supplied tenant_id
def vulnerable_get_users(request):
    # ├ Taking tenant from user input
    tenant_id = request.args.get('tenant_id')
    users = db.query("SELECT * FROM users WHERE tenant_id = %s", (tenant_id,))
    return users  # User can access ANY tenant's data!

# ├ CORRECT: Extract tenant from authenticated session
def secure_get_users(request):
    user = get_authenticated_user(request)
    tenant_id = user.tenant_id  # From session, not user input
    users = db.query(
        "SELECT * FROM users WHERE tenant_id = %s",
        (tenant_id,)
    )
    return users


### ├ WRONG: Exposing All Data Fields (OWASP A01)

python
# MAY EXPOSE SENSITIVE DATA
def get_user_profile(user_id: str):
    user = db.get_user(user_id)
    # ├ Returns ALL fields including sensitive ones
    return user.__dict__

# ├ CORRECT: Explicitly return only needed fields
def get_user_profile(user_id: str, requesting_user):
    user = db.get_user(user_id)
    
    # Return different fields based on authorization
    if requesting_user.id == user_id:
        # User viewing their own profile
        return {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'phone': user.phone,
            'address': user.address
        }
    else:
        # Others viewing profile - limited data
        return {
            'id': user.id,
            'name': user.name,
            'public_email': user.public_email
        }


### ├ WRONG: Logging Sensitive Data (OWASP A09)

python
# EXPOSES SENSITIVE DATA IN LOGS
def bad_logging(request, user):
    # ├ Logging request body - may contain passwords
    logger.info(f"Request body: {request.body}")
    
    # ├ Logging PII
    logger.info(f"Processing user: {user.ssn}, email: {user.email}")
    
    # ├ Logging authentication tokens
    logger.info(f"Auth token: {request.headers.get('Authorization')}")

# ├ CORRECT: Log only non-sensitive data
def good_logging(request, user):
    logger.info(f"Request received", extra={
        'user_id': user.id,
        'action': 'profile_update',
        'ip': request.remote_addr,
        'timestamp': datetime.utcnow()
    })


### ├ WRONG: Insecure Deserialization (OWASP A08)

python
import pickle

# REMOTE CODE EXECUTION RISK
def vulnerable_deserialize(user_data: bytes):
    # ├ NEVER use pickle with untrusted data
    obj = pickle.loads(user_data)
    return obj

def vulnerable_eval(user_input: str):
    # ├ NEVER use eval() with user input
    result = eval(user_input)
    return result

# ├CORRECT: Use safe serialization
import json

def secure_deserialize(user_data: str):
    # Use JSON for safe deserialization
    try:
        obj = json.loads(user_data)
        # Validate the structure
        validate_schema(obj)
        return obj
    except json.JSONDecodeError:
        raise ValueError("Invalid data format")


### Sensitive Field Patterns

Watch for these field name patterns and apply appropriate protection:
- *Credentials*: passwords, tokens, secrets, api_keys ├ Hash/encrypt, never return
- *PII*: ssn, national_id, passport, license ├ Encrypt at rest, strict access control
- *Financial*: salary, compensation, bank_account, card_number ├ Encrypt, admin-only access
- *Flags*: is_admin, is_active, is_verified ├ Server-side only, never trust client
- *Dates*: expiration_date, termination_date ├ Server-controlled, prevent manipulation

### Numeric Validation Best Practices

python
def validate_price(price: Any) -> float:
    """Validate monetary amount"""
    try:
        amount = float(price)
        
        # Reject negative values (including -0)
        if amount < 0 or (amount == 0 and str(price).startswith('-')):
            raise ValueError("Price cannot be negative")
        
        # Validate reasonable range
        if amount > 1000000:  # Adjust as needed
            raise ValueError("Price exceeds maximum")
        
        # Round to 2 decimal places for currency
        return round(amount, 2)
    except (ValueError, TypeError):
        raise ValueError("Invalid price format")

def validate_quantity(qty: Any) -> int:
    """Validate integer quantity"""
    try:
        quantity = int(qty)
        if quantity < 0:
            raise ValueError("Quantity cannot be negative")
        if quantity > 10000:  # Reasonable limit
            raise ValueError("Quantity exceeds maximum")
        return quantity
    except (ValueError, TypeError):
        raise ValueError("Invalid quantity")

## Rate Limiting (OWASP A07: Authentication Failures Prevention)

### When to Implement Rate Limiting

**REQUIRED for:**
- Login attempts (prevent brute force)
- OTP/MFA validation
- Password reset requests
- Any endpoint sending emails/SMS
- Unauthenticated/public endpoints
- Resource-intensive operations

### Python Implementation Example

python
from functools import wraps
from time import time
from collections import defaultdict
from typing import Callable

# Simple in-memory rate limiter (use Redis for production)
rate_limit_storage = defaultdict(list)

def rate_limit(max_attempts: int, window_seconds: int, key_func: Callable = None):
    """
    Rate limiting decorator
    
    Args:
        max_attempts: Maximum number of attempts allowed
        window_seconds: Time window in seconds
        key_func: Function to generate rate limit key (user_id, IP, etc.)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            # Generate rate limit key
            if key_func:
                limit_key = key_func(request)
            else:
                # Default to user ID or IP
                limit_key = getattr(request, 'user_id', None) or request.remote_addr
            
            current_time = time()
            
            # Clean old attempts outside the window
            rate_limit_storage[limit_key] = [
                t for t in rate_limit_storage[limit_key]
                if current_time - t < window_seconds
            ]
            
            # Check if limit exceeded
            if len(rate_limit_storage[limit_key]) >= max_attempts:
                # Log the rate limit violation
                log_security_event('rate_limit_exceeded', key=limit_key)
                return {"error": "Too many requests. Please try again later."}, 429
            
            # Record this attempt
            rate_limit_storage[limit_key].append(current_time)
            
            return func(request, *args, **kwargs)
        return wrapper
    return decorator

# Usage examples
@rate_limit(max_attempts=5, window_seconds=300)  # 5 attempts per 5 minutes
def login(request):
    username = request.data.get('username')
    password = request.data.get('password')
    # Login logic here
    pass

@rate_limit(max_attempts=3, window_seconds=3600)  # 3 attempts per hour
def reset_password(request):
    email = request.data.get('email')
    # Send password reset email
    pass


**Best Practices:**
- Use user-based keys when authenticated (tracks per-user)
- Use IP-based keys for unauthenticated endpoints
- Set conservative limits: 3-10 for auth, 5-20 for email sends
- Log rate limit violations for security monitoring
- Use distributed cache (Redis) for production environments
- Return generic error messages (don't reveal limit details)

## Security Testing (OWASP Testing)

### Multi-Tenant Isolation Testing (OWASP A01)

python
import requests

def test_cross_tenant_access():
    """Test that users cannot access other tenants' data"""
    
    # Step 1: Create two test tenants
    tenant_a = create_test_tenant("Tenant A")
    tenant_b = create_test_tenant("Tenant B")
    
    # Step 2: Create users in each tenant
    user_a = create_user(tenant_a, "user_a@example.com")
    user_b = create_user(tenant_b, "user_b@example.com")
    
    # Step 3: Get auth tokens
    token_a = authenticate(user_a)
    token_b = authenticate(user_b)
    
    # Step 4: Try to access Tenant A's data with Tenant B's credentials
    response = requests.get(
        f"/api/users/{user_a.id}",
        headers={"Authorization": f"Bearer {token_b}"}
    )
    
    # Should be denied
    assert response.status_code == 403, "Cross-tenant access should be denied!"
    
    print("├ Cross-tenant isolation working correctly")

### Security Test Checklist

python
def security_test_suite():
    """Comprehensive security testing"""
    
    # OWASP A01: Broken Access Control
    test_unauthenticated_access_denied()
    test_user_cannot_access_others_data()
    test_user_cannot_escalate_privileges()
    test_admin_scoped_to_tenant()
    
    # OWASP A03: Injection
    test_sql_injection_prevention()
    test_xss_prevention()
    test_command_injection_prevention()
    
    # OWASP A07: Authentication Failures
    test_brute_force_protection()
    test_session_timeout()
    test_password_complexity()
    test_mfa_enforcement()
    
    # OWASP A09: Logging
    test_security_events_logged()
    test_no_sensitive_data_in_logs()


## Secrets Management (OWASP A02: Cryptographic Failures)

### Storage Best Practices

- **Secrets Manager**: AWS Secrets Manager
- **Environment Variables**: For development only (use .env files, never commit)
- **Key Management Service**: For encryption keys (AWS KMS, Google Cloud KMS)
- **NEVER**: Hardcode in code, commit to version control, store in databases as plaintext

### Python Implementation

python
import os
from typing import Optional

class SecretsManager:
    """Secure secrets management"""
    
    def __init__(self):
        # In production: use actual secrets manager (AWS, Vault, etc.)
        # In development: use environment variables
        self.is_production = os.getenv('ENV') == 'production'
    
    def get_secret(self, secret_name: str) -> Optional[str]:
        """Get secret from secure storage"""
        if self.is_production:
            # Production: Use secrets manager
            return self._get_from_secrets_manager(secret_name)
        else:
            # Development: Use environment variables
            secret = os.getenv(secret_name)
            if not secret:
                raise ValueError(f"Secret '{secret_name}' not found")
            return secret
    
    def _get_from_secrets_manager(self, secret_name: str) -> str:
        """Fetch from AWS Secrets Manager / Vault"""
        # Implementation depends on your secrets manager
        # Example for AWS:
        # import boto3
        # client = boto3.client('secretsmanager')
        # response = client.get_secret_value(SecretId=secret_name)
        # return response['SecretString']
        pass

# Usage
secrets = SecretsManager()
db_password = secrets.get_secret('DATABASE_PASSWORD')
api_key = secrets.get_secret('THIRD_PARTY_API_KEY')


### Environment Variables (Development Only)

python
# .env file (NEVER commit to git!)
DATABASE_PASSWORD=your_password_here
API_KEY=your_api_key_here
SECRET_KEY=your_secret_key_here

# .gitignore
.env
*.env
.env.*


```python
# Load environment variables
from dotenv import load_dotenv
import os

load_dotenv()  # Load from .env file

DATABASE_PASSWORD = os.getenv('DATABASE_PASSWORD')
if not DATABASE_PASSWORD:
    raise ValueError("DATABASE_PASSWORD not set")
```


### If Secret is Exposed

*Immediate Actions:*
1. *IMMEDIATELY* revoke/rotate the exposed secret
2. Generate new secret using cryptographically secure method
3. Store new secret in secrets manager (not in code)
4. Don't just delete from git - it's in history permanently
5. Consider using tools like git-secrets or trufflehog to scan history
6. Alert security team and document the incident
7. Review access logs to check if secret was used maliciously

python
import secrets

def generate_secure_secret(length: int = 32) -> str:
    """Generate cryptographically secure random secret"""
    return secrets.token_urlsafe(length)

# Generate new API key
new_api_key = generate_secure_secret(32)


## XSS Prevention (OWASP A03: Injection)


# Usage in templates (Jinja2 example)
from jinja2 import Environment, select_autoescape

env = Environment(autoescape=select_autoescape(['html', 'xml']))

# Template automatically escapes variables
template = env.from_string('<h1>{{ user_name }}</h1>')
safe_output = template.render(user_name=user_input)


### Context-Specific Encoding

python
import json
import urllib.parse

def encode_for_html(data: str) -> str:
    """Encode for HTML context"""
    return html.escape(data)

def encode_for_javascript(data: str) -> str:
    """Encode for JavaScript context"""
    return json.dumps(data)[1:-1]  # Remove quotes

def encode_for_url(data: str) -> str:
    """Encode for URL context"""
    return urllib.parse.quote(data)

# Example: Rendering data in different contexts
html_safe = encode_for_html(user_input)
js_safe = encode_for_javascript(user_input)
url_safe = encode_for_url(user_input)


### Content Security Policy (CSP)

python
def set_security_headers(response):
    """Set security headers including CSP"""
    
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://trusted-cdn.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self' https://api.example.com; "
        "frame-ancestors 'none'"
    )
    
    # Additional security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response


## SSRF Prevention

### URL Validation

python
from urllib.parse import urlparse
import ipaddress

def is_safe_url(url):
    """Validate URL to prevent SSRF attacks"""
    try:
        parsed = urlparse(url)
        
        # Only allow http/https
        if parsed.scheme not in ('http', 'https'):
            return False
        
        # Resolve hostname to IP
        ip = ipaddress.ip_address(parsed.hostname)
        
        # Block private IPs
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
            
        return True
    except:
        return False

# Always validate URLs from user input
url = request.data.get('url')
if not is_safe_url(url):
    raise ValidationError("Invalid URL")


### File Upload Security

For file uploads accepting URLs:
- Validate URL scheme (only http/https)
- Check for private/internal IPs
- Implement allowlist for trusted domains
- Use cloud storage with restricted access

## Internal / Admin APIs (OWASP A01: Broken Access Control)

For internal admin tools or privileged endpoints:

python
from functools import wraps
import logging

audit_logger = logging.getLogger('security.audit')

def require_admin(func):
    """Decorator to require admin privileges"""
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        user = get_authenticated_user(request)
        
        if not user.is_admin:
            audit_logger.warning(
                f"Unauthorized admin access attempt by user {user.id}"
            )
            return {"error": "Admin access required"}, 403
        
        return func(request, *args, **kwargs)
    return wrapper

def require_super_admin(func):
    """Decorator for super admin only endpoints"""
    @wraps(func)
    def wrapper(request, *args, **kwargs):
        user = get_authenticated_user(request)
        
        if not user.is_super_admin:
            audit_logger.warning(
                f"Unauthorized super admin access attempt by user {user.id}"
            )
            return {"error": "Super admin access required"}, 403
        
        # Additional checks for production data access
        tenant_id = kwargs.get('tenant_id')
        if is_production_tenant(tenant_id):
            if not user.has_permission('access_production_data'):
                audit_logger.error(
                    f"Production access denied for user {user.id}"
                )
                return {"error": "Production access not authorized"}, 403
        
        # Log admin access for audit trail
        audit_logger.info(
            f"Admin action",
            extra={
                'admin_user_id': user.id,
                'target_tenant': tenant_id,
                'action': func.__name__,
                'timestamp': datetime.utcnow()
            }
        )
        
        return func(request, *args, **kwargs)
    return wrapper

# Usage
@require_admin
def admin_view_users(request, tenant_id):
    """Admin endpoint with audit logging"""
    users = get_users_for_tenant(tenant_id)
    return users

@require_super_admin
def super_admin_delete_tenant(request, tenant_id):
    """Highly privileged operation"""
    delete_tenant(tenant_id)
    return {"status": "deleted"}


### Admin Access Control Checklist

- [ ] Implement role-based access control (admin, super_admin, etc.)
- [ ] Not all admins should access everything (principle of least privilege)
- [ ] Extra protection for production tenant data
- [ ] Comprehensive audit logging with admin user ID, target, action, timestamp
- [ ] Don't expose highly sensitive data even to admins
- [ ] Require additional authentication (MFA) for destructive operations
- [ ] Test that only authorized admins have access
- [ ] Implement session timeouts for admin sessions
- [ ] Alert on suspicious admin activities

## Quick Reference: Python Security Patterns

### Essential Security Libraries

python
# Cryptography
import secrets  # Secure random number generation
import hashlib  # Hashing (use with salt)
from cryptography.fernet import Fernet  # Symmetric encryption
import bcrypt  # Password hashing

# Input Validation & Sanitization
import re  # Regular expressions for validation
import html  # HTML escaping
import bleach  # HTML sanitization with allowlist
from markupsafe import escape  # Template escaping

# SQL Injection Prevention
# Use parameterized queries with your database library
# SQLAlchemy, psycopg2, pymongo, etc.

# XML Security
import defusedxml.ElementTree as ET  # Safe XML parsing

# Environment & Secrets
from dotenv import load_dotenv  # Load .env files
import os  # Access environment variables


### Common Security Patterns

python
# Authentication decorator
@require_authentication
def protected_endpoint(request):
    pass

# Authorization decorator
@require_permission('view_users')
def authorized_endpoint(request):
    pass

# Rate limiting
@rate_limit(max_attempts=5, window_seconds=300)
def rate_limited_endpoint(request):
    pass

# Admin-only access
@require_admin
def admin_endpoint(request):
    pass

# Input validation
validated_email = validate_email(user_input)
validated_price = validate_price(user_input)

# Output encoding
safe_html = html.escape(user_input)
safe_url = urllib.parse.quote(user_input)

# Secure file handling
safe_filename = sanitize_filename(original_filename)
secure_path = generate_secure_file_path(user_id, safe_filename)


### OWASP Top 10 Quick Checklist

- *A01*: Verify authorization on every request, never trust client-supplied IDs
- *A02*: Use TLS, encrypt sensitive data at rest, use strong crypto (bcrypt, AES-256)
- *A03*: Parameterized queries, input validation, output encoding, defusedxml
- *A07*: MFA, secure sessions, rate limiting, strong passwords
- *A09*: Log security events, never log PII/passwords, implement monitoring

## When to Contact Security Team

*REQUIRED security review for:*
- Unauthenticated endpoints
- New third-party authentication methods
- WebHook implementations
- Exposing APIs to third-party vendors
- Making endpoints publicly accessible
- Using legacy authentication patterns
- Using XML parsing or templating systems
- Switching database systems
- Accepting system commands from user input
- Modifying CSP, CORS, or security headers
- Any cross-tenant data access requirements
- Implementing new cryptographic functions

*Contact:* Your organization's security team or security@yourcompany.com

## Additional Resources

- reference/authentication.md - Authentication deep dive
- reference/authorization.md - Authorization and permissions
- reference/data-security.md - Data handling, encryption, logging
- reference/api-development.md - API development patterns
- reference/file-processing.md - File processing security standards

## Remember

1. *Security is not optional* - Follow these patterns consistently
2. *When in doubt, ask* - Consult your security team
3. *Test your code* - Use two test tenants to test multi-tenant isolation
4. *Explicit is better* - List fields explicitly, validate explicitly
5. *Defense in depth* - Multiple layers of security checks
6. *Assume breach* - Design systems with the assumption that some component may be compromised