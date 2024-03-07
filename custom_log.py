"""
Module for Custom Logging
"""
import datetime
import logging
from logging.handlers import RotatingFileHandler
import os
from sqlalchemy import create_engine, text
from common_functions import _config, credential_decrypter


class CustomLogger:
    """
    Custom Logger Class
    """

    def __init__(self):
        self.base_dir = os.path.dirname(__file__)
        self.log_file = os.path.join(self.base_dir, _config['logging']['log_file_path'])
        max_file_size = _config['logging']['max_file_size']
        backup_count = _config['logging']['backup_count']
        self.dbname = _config['mariadb']['database']
        self.hostname = _config['mariadb']['host']
        self.user = _config['mariadb']['username']
        self.password = credential_decrypter(_config['mariadb']['pd'])
        self.log_table_name = _config['logging']['log_table_name']
        self.engine = create_engine(
            "mysql+pymysql://{user}:{pw}@{host}/{db}".format(host=self.hostname, db=self.dbname,
                                                             user=self.user, pw=self.password))
        self.logger = logging.getLogger()

        handler = RotatingFileHandler(self.log_file, maxBytes=max_file_size,
                                      backupCount=backup_count)
        handler.setLevel(logging.DEBUG)

        formatter = logging.Formatter('%(asctime)s - %(hostname)s: %(message)s')
        handler.setFormatter(formatter)

        self.logger.addHandler(handler)

    def _log(self, message, hostname):
        """
        This method logs a message to the log directory defined

        Args:
            message: The message to be logged
            hostname: The name of host for which log is generated

        Returns:

        """
        extra = {'hostname': hostname} if hostname else {}
        self.logger.log(level=logging.CRITICAL, msg=message, extra=extra)

    def db_log(self, message, hostname=None):
        """
        This method logs a message to the database

        Args:
            message: The message to be logged
            hostname: The name of host for which log is generated

        Returns:

        """
        statement = _config['logging']['log_table_sql_statement']
        log_timestamp_generated = datetime.datetime.now()
        log_msg = str(log_timestamp_generated) + " - " + message
        statement = statement.format(hostname=hostname, log=log_msg,
                                     log_timestamp=log_timestamp_generated)
        try:
            with self.engine.connect() as connection:
                connection.execute(text(statement))
                connection.close()
        except Exception as error:
            log_msg = f"Unable to log the messages to database\nError: {error}"
            self._log(message=log_msg, hostname='NA')
