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


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check if a plain-text password matches a hashed password using bcrypt.

    Args:
        hashed_password (bytes): The stored hashed password.
        password (str): The plain-text password to be validated.

    Returns:
        bool: True if the plain-text password matches the hashed password,
              False otherwise.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
