#!/usr/bin/env python3
"""
encrypt_password
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hash a password using bcrypt.

    Args:
        password (str): The plain-text password to be hashed.

    Returns:
        bytes: The salted, hashed password as a byte string.
    """
    return bcrypt.hashpw(password.encode('utf-8'),
                         salt=bcrypt.gensalt())
