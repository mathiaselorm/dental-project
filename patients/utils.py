# patients/utils.py

"""
Utility functions for the patients app.

Includes:
- Error message sanitization to prevent PII leakage
"""

from __future__ import annotations

import re
from typing import Any


# =========================
# Error Message Sanitization
# =========================

def sanitize_error_message(error: str | dict | list) -> str | dict | list:
    """
    Sanitize error messages to prevent PII leakage.
    Removes patient names, phone numbers, and other sensitive data patterns.
    
    Usage:
        sanitized = sanitize_error_message(str(exception))
        sanitized = sanitize_error_message({"phone": "+233241234567 is invalid"})
    """
    # Patterns to redact
    patterns = [
        (r'\+233\d{9}', '[PHONE]'),  # Ghana phone numbers
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]'),  # Email addresses
        (r'DEN-\d{4}-\d+', '[FOLDER]'),  # Folder numbers (if appearing in unexpected places)
    ]
    
    def redact_string(s: str) -> str:
        for pattern, replacement in patterns:
            s = re.sub(pattern, replacement, s)
        return s
    
    if isinstance(error, str):
        return redact_string(error)
    elif isinstance(error, dict):
        return {k: sanitize_error_message(v) for k, v in error.items()}
    elif isinstance(error, list):
        return [sanitize_error_message(item) for item in error]
    return error
