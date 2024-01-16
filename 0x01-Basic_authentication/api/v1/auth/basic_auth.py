#!/usr/bin/env python3
""" BasicAuth module for handling basic authentication logic
"""
import base64
from typing import TypeVar
from models.user import User
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """ BasicAuth class inherits from Auth for handling
        basic authentication logic
    """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """ Extract the base64-encoded credentials from
            the Authorization header.

        Args:
            authorization_header: The Authorization header value.

        Returns:
            str: The base64-encoded credentials if valid,
                 otherwise returns None.
        """
        if (
            not authorization_header
            or not isinstance(authorization_header, str)
            or not authorization_header.startswith('Basic ')
        ):
            return None

        # Extract and return the base64-encoded credentials
        return authorization_header.split()[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """ Decode a base64-encoded string and return the
            decoded value as UTF-8.

        Args:
            base64_authorization_header (str): The base64-encoded string.

        Returns:
            str: The decoded value as UTF-8 if valid, otherwise returns None.
        """
        if (
            base64_authorization_header is None
            or not isinstance(base64_authorization_header, str)
        ):
            return None

        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except base64.binascii.Error:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """ Extract user email and password from the decoded
            base64 authorization header.

        Args:
            decoded_base64_authorization_header: The decoded base64
                                                 authorization header.

        Returns:
            Tuple: The user email and password if valid,
                   otherwise (None, None).
        """
        if (
            decoded_base64_authorization_header is None
            or not isinstance(decoded_base64_authorization_header, str)
            or ':' not in decoded_base64_authorization_header
        ):
            return None, None

        user_email, user_pwd = decoded_base64_authorization_header.split(':')

        return user_email, user_pwd

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """ user_object_from_credentials
        """
        if not user_email or not user_pwd:
            return None
        return User.search({'email': user_email})[0]
