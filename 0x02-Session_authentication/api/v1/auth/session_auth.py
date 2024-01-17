#!/usr/bin/env python3
""" SessionAuth module for handling session authentication logic
"""
from uuid import uuid4
from models.user import User
from api.v1.auth.auth import Auth


class SessionAuth(Auth):
    """ SessionAuth class inherits from Auth for handling
        session authentication logic
    """
    user_id_by_session_id: dict = {}

    def create_session(self, user_id: str = None) -> str:
        """ Create a Session ID for the given user_id.

        Args:
            user_id: The ID of the user for whom the session
                     is created. Defaults to None.

        Returns:
            The generated Session ID.
        """
        if not isinstance(user_id, str):
            return None
        session_id = str(uuid4())
        self.user_id_by_session_id[session_id] = user_id

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """ Get the User ID associated with the given Session ID.

        Args:
            session_id: The Session ID for which to retrieve the
                        associated User ID. Defaults to None.

        Returns:
            The User ID associated with the provided Session ID,
            or None if not found.
        """
        if not isinstance(session_id, str):
            return None
        user_id = self.user_id_by_session_id.get(session_id)

        return user_id

    def current_user(self, request=None):
        """ Get the current user in the current session

        Args:
            request: The Flask request object. Defaults to None.

        Return:
            The current user instance
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        user = User.get(user_id)

        return user

    def destroy_session(self, request=None):
        """ deletes the user session and logout

        Args:
            request: The Flask request object. Defaults to None.

        Return:
            True if successful, False otherwise
        """
        if not request:
            return False

        session_id = self.session_cookie(request)

        if not self.user_id_for_session_id(session_id):
            return False

        del self.user_id_by_session_id[session_id]

        return True
