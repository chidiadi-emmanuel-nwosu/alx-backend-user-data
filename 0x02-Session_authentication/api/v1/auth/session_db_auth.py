#!/usr/bin/env python3
""" SessionDBAuth module for handling session authentication logic
"""
from typing import Union
from datetime import datetime, timedelta
from api.v1.auth.session_exp_auth import SessionExpAuth
from models.user_session import UserSession


class SessionDBAuth(SessionExpAuth):
    """ SessionExpAuth class inherits from SessionAuth for handling
        session authentication logic with expiration
    """

    def create_session(self, user_id: str = None) -> Union[str, None]:
        """ Create a Session ID for the given user_id.

        Args:
            user_id: The ID of the user for whom the session
                     is created. Defaults to None.

        Returns:
          - The generated Session ID, None if not created
        """
        session_id = super().create_session(user_id)
        if not session_id:
            return None

        kwargs = self.user_id_by_session_id.get(session_id)
        user_session = UserSession(kwargs)
        user_session.save()

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

        session_dict = UserSession.search({'session_id': session_id})
        if not session_dict:
            return None

        for _dict in session_dict:
            if _dict.session_id == session_id:
                created_at = _dict.get('created_at')
                user_id = _dict.get('user_id')

        if self.session_duration <= 0:
            return user_id

        if not created_at:
            return None

        exp_time = created_at + timedelta(seconds=self.session_duration)
        if exp_time < datetime.now():
            return None

        return user_id

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

        session_dict = UserSession.search({'session_id': session_id})
        if not session_dict:
            return False

        for _dict in session_dict:
            if _dict.session_id == session_id:
                _dict.remove()
                return True

        return False
