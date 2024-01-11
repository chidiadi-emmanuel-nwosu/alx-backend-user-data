#!/usr/bin/env python3
"""
filtered_logger: A module for logging with data redaction functionality.
"""
import os
import re
import logging
from typing import List
import mysql.connector


PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


class RedactingFormatter(logging.Formatter):
    """
    Custom logging formatter that redacts sensitive
    information (PII) from log messages.

    Attributes:
        REDACTION (str): The string used for redacting sensitive information.
        FORMAT (str): The log message format.
        SEPARATOR (str): The separator used to identify key-value
                          pairs in log messages.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initialize the RedactingFormatter.

        Args:
            fields (List[str]): A list of field names representing sensitive
                                information to redact.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format a log record, redacting sensitive information.

        Args:
            record (logging.LogRecord): The log record to be formatted.

        Returns:
            str: The formatted log message with redacted sensitive information.
        """
        message = super(RedactingFormatter, self).format(record)
        return filter_datum(self.fields, self.REDACTION,
                            message, self.SEPARATOR)


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """
    Obfuscates specific fields within a log message.

    Args:
        fields (List[str]): A list of field names to be redacted.
        redaction (str): The string to replace redacted information.
        message (str): The log message containing sensitive information.
        separator (str): The separator used to identify key-value pairs
                         in the log message.

    Returns:
        str: The log message with specified fields redacted.
    """
    return re.sub(r'({})=[^{}]+'.format('|'.join(fields), separator),
                  r'\1={}'.format(redaction), message)


def get_logger() -> logging.Logger:
    """
    Get a configured logger instance for logging user data with redaction.

    Returns:
        logging.Logger: The configured logger instance.
    """
    logger = logging.getLogger('user_data')
    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = RedactingFormatter(PII_FIELDS)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    A connector to the MySQL database.

    Returns:
        Database connector object.
    """
    db_username = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME")

    return mysql.connector.connect(
            user=db_username,
            password=db_password,
            host=db_host,
            database=db_name
            )


def main():
    """
    Obtain a database connection, retrieve all rows from the 'users' table,
    and display each row in a filtered format. Print a list of filtered fields.
    """
    db_connection = get_db()
    cursor = db_connection.cursor()
    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()

    logger = get_logger()

    for row in rows:
        msg = '; '.join([f"{field}={value}" for field, value in row.items()])
        logger.info(filter_datum(PII_FIELDS, RedactingFormatter.REDACTION,
                                 msg, RedactingFormatter.SEPARATOR))


if __name__ == "__main__":
    main()
