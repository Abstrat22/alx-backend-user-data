#!/usr/bin/env python3

"""
Hashes and validates passwords using the bcrypt library.
"""

import bcrypt

def hash_password(password: str) -> bytes:
    """
    Returns a hashed password.
    
    Args:
        password (str): The password to be hashed.
    
    Returns:
        bytes: The hashed password.
    """
    password_bytes = password.encode()
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed

def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Checks whether a password is valid.

    Args:
        hashed_password (bytes): The hashed password.
        password (str): The password in plain text.

    Returns:
        bool: True if the password is valid, False otherwise.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)

