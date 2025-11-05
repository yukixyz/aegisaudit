# Aegis Audit

Inspector-Safe is a non-destructive, authorization-first auditing tool for passive enumeration and configuration checks.
It is intended for legal, consented security assessments only. Use only with explicit written authorization.

Features
- DNS enumeration (A, AAAA, MX, NS, TXT)
- HTTP header analysis via safe HEAD requests
- Banner grabbing for common services using a short timeout and single read
- Token-based authorization enforced by default
- Rate limiting and concurrency control
- Structured JSON reports with timestamps
- Rotating logs and comprehensive CLI
- Tests for core behaviors

Quickstart
1. Create a virtual environment and install requirements
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt

2. Add authorized tokens to authorized_tokens.json
   [{"name": "work", "token": "your-token-here"}]

3. Run a basic scan
   python -m inspector_safe.cli scan example.com --auth-token your-token-here --output reports

Legal Notice
Only run this tool against systems for which you have explicit authorization.
The authors are not responsible for misuse.

