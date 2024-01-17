#!/usr/bin/env python3
""" SessionAuth module for handling session authentication logic
"""
from os import getenv
from typing import Union
from datetime import datetime, timedelta
from api.v1.auth.session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """ SessionExpAuth class inherits from SessionAuth for handling
        session authentication logic with expiration
    """
    def __init__(self):
        """ Initialize SessionExpAuth instance
        """
        duration = getenv('SESSION_DURATION', '0')
        try:
            self.session_duration = int(duration)
        except ValueError:
            self.session_duration = 0

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

        session_dict = {
                'user_id': user_id,
                'created_at': datetime.now()
                }
        self.user_id_by_session_id[session_id] = session_dict

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

        session_dict = self.user_id_by_session_id.get(session_id)
        if not session_dict:
            return None

        created_at = session_dict.get('created_at')
        user_id = session_dict.get('user_id')

        if self.session_duration <= 0:
            return user_id

        exp_time = created_at + timedelta(seconds=self.session_duration)
        if exp_time < datetime.now():
            return None

        return user_id
