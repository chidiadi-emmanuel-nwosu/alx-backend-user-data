#!/usr/bin/env python3
"""main modules
"""
import requests
import json

EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"

BASE_URL = "http://127.0.0.1:5000"


def register_user(email: str, password: str) -> None:
    """register a user
    """
    end_point = f"{BASE_URL}/users"
    data = {'email': email, 'password': password}
    response = requests.post(end_point, data=data)
    assert response.status_code == 200


def log_in_wrong_password(email: str, password: str) -> None:
    """login with wrong password
    """
    end_point = f"{BASE_URL}/sessions"
    data = {'email': email, 'password': password}
    response = requests.post(end_point, data=data)
    assert response.status_code == 401


def log_in(email: str, password: str) -> str:
    """login
    """
    end_point = f"{BASE_URL}/sessions"
    data = {'email': email, 'password': password}
    response = requests.post(end_point, data=data)
    assert response.status_code == 200

    return response.cookies.get('session_id')


def profile_unlogged() -> None:
    """profile_unlogged
    """
    end_point = f"{BASE_URL}/profile"
    response = requests.get(end_point)

    print(response.status_code, response.text)
    assert response.status_code == 403


def profile_logged(session_id: str) -> None:
    """profile_logged
    """
    end_point = f"{BASE_URL}/profile"
    response = requests.get(end_point, cookies=session_id)
    assert response.status_code == 200


def log_out(session_id: str) -> None:
    """log_out
    """
    end_point = f"{BASE_URL}/sessions"
    response = requests.delete(end_point, cookies=session_id)
    assert response.status_code == 200


def reset_password_token(email: str) -> str:
    """reset_password_token
    """
    end_point = f"{BASE_URL}/reset_password"
    data = {'email': email}
    response = requests.post(end_point, data=data)
    assert response.status_code == 200

    response = json.loads(response.text)
    return response['reset_token']


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """update_password
    """
    end_point = f"{BASE_URL}/reset_password"
    data = {'email': email, 'reset_token': reset_token,
            'new_password': new_password}
    response = requests.put(end_point, data=data)
    assert response.status_code == 200


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
