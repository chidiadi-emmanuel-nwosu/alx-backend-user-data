#!/usr/bin/env python3
""" Auth module for handling authentication logic
"""
from typing import List, TypeVar


class Auth:
    """ Auth class for handling authentication logic
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Check if authentication is required for the given path.

        Args:
            path: The path to check for authentication requirement.
            excluded_paths: List of paths where authentication is not required.

        Returns:
            bool: True if authentication is required, False otherwise.
        """
        if not path or not excluded_paths:
            return True

        for excluded_path in excluded_paths:
            if excluded_path.endswith('*'):
                if path.startswith(excluded_path[:-1]):
                    return False
            elif excluded_path in (path, path + '/'):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """Extract the Authorization header from the provided Flask request.

        Args:
            request (flask.Request, optional): The Flask request object.

        Returns:
            str: The Authorization header value if present,
                 otherwise returns None.
        """
        return None if not request else request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """ current_user
        """
        return None
