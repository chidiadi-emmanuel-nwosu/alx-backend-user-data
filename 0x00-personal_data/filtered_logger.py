#!/usr/bin/env python3
"""
filtered_logger
"""
import re
import logging
from typing import List, Iterable


PII_FIELDS = ('name', 'email', 'ssn', 'password', 'ip')


def filter_datum(fields: List, redaction: str, message: str, separator: str) -> str:
    """ Obfuscates specific fields within a log message. """
    return re.sub(fr'({"|".join(map(re.escape, fields))})=[^{re.escape(separator)}]+',
                  fr'\1={redaction}', message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List):
        """ initilise
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """ format logger
        """
        message = super().format(record)
        return filter_datum(self.fields, self.REDACTION, message, self.SEPARATOR)


def get_logger() -> logging.Logger:
    """ get_logger
    """
    logger = logging.getLogger('user_data')
    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = RedactingFormatter(PII_FIELDS)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    return logger
