#!/usr/bin/env python3
"""
filtered_logger: A module for logging with data redaction functionality.
"""
import re
import logging
from typing import List
import mysql.connector
from os import getenv


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


def get_db() -> mysql.connector.MySQLConnection:
    """
    Returns a connector to the MySQL database.
    """
    return mysql.connector.connect(
        user=getenv("PERSONAL_DATA_DB_USERNAME", "root"),
        password=getenv("PERSONAL_DATA_DB_PASSWORD", ""),
        host=getenv("PERSONAL_DATA_DB_HOST", "localhost"),
        database=getenv("PERSONAL_DATA_DB_NAME")
    )
