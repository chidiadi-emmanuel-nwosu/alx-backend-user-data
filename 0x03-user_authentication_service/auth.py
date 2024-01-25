#!/usr/bin/env python3
"""auth module
"""
from uuid import uuid4
from sqlalchemy.orm.exc import NoResultFound
from bcrypt import hashpw, gensalt, checkpw
from db import DB
from user import User


def _hash_password(password):
    """Hashes a password
    """
    return hashpw(password.encode('utf-8'), gensalt())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initialize
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a user
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        raise ValueError(f'User {user.email} already exists')

    def valid_login(self, email: str, password: str) -> bool:
        """checks a valid login
        """
        try:
            user = self._db.find_user_by(email=email)
            return checkpw(password.encode('utf-8'),
                           user.hashed_password)
        except NoResultFound:
            return False

    def _generate_uuid(self) -> str:
        """Generates a token
        """
        return str(uuid4())

    def create_session(self, email: str) -> str:
        """returns a session string
        """
        user = self._db.find_user_by(email=email)
        session_id = str(uuid4())
        self._db.update_user(user.id, session_id=session_id)

        return session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        """returns a session string
        """
        try:
            return self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """destroys a session string
        """
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """returns a password reset token
        """
        try:
            user = self._db.find_user_by(email=email)
            reset_token = str(uuid4())
            self._db.update_user(user.id, reset_token=reset_token)

            return reset_token
        except NoResultFound as exc:
            raise ValueError from exc

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates user password
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            self._db.update_user(user.id,
                                 hashed_password=_hash_password(password))
        except NoResultFound as exc:
            raise ValueError from exc
