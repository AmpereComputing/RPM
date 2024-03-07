"""
Module to rotate Root Password
"""
import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import secrets
import smtplib
import string
import threading
import time
import paramiko
from sqlalchemy import create_engine, text
from common_functions import _config, credential_decrypter, credential_encrypter
from custom_log import CustomLogger


class Rotation:
    """
    Class for Password Rotation
    """

    def __init__(self):
        """
        init method which initialises all the class variables
        """
        self.base_dir = os.path.dirname(__file__)
        self.dbname = _config['mariadb']['database']
        self.hostname = _config['mariadb']['host']
        self.user = _config['mariadb']['username']
        self.password = credential_decrypter(_config['mariadb']['pd'])
        self.engine = create_engine(f"mysql+pymysql://{self.user}:{self.password}"
                                    f"@{self.hostname}/{self.dbname}")
        self.password_length = _config['linux']['password_length']
        self.max_attempts = _config['ssh']['max_attempts']
        self.server_username = _config['ssh']['username']
        self.server_password = credential_decrypter(_config['ssh']['pd'])
        self.root_pass_change_cmd = _config['ssh']['root_pass_change_cmd']
        custom_logger_obj = CustomLogger()
        self.file_log = custom_logger_obj._log
        self.db_log = custom_logger_obj.db_log
        self.password_change_success_host_list = []
        self.password_change_fail_host_list = []
        self.old_passwords = self.get_old_password()
        self.new_password_generated = self.generate_random_password(self.password_length)

    def run(self):
        """
        Main method of the class
        """
        with open(os.path.join(self.base_dir, _config['linux']['hosts_list_file'])) as hosts:
            hostnames_list = [str(line.strip()) for line in hosts]
        threads_list = []
        for host in hostnames_list:
            thread = threading.Thread(target=self.set_root_password,
                                      args=(host, self.new_password_generated))
            threads_list.append(thread)
            thread.start()

        for thread in threads_list:
            thread.join()
        self.send_mail()

    def generate_random_password(self, pass_len):
        """
        This method will generate a random password of the given length and verifies whether this
        password is already used or not by calling get_password_history() function internally. If
        it is used it will generate another make sure that every time a new password is
        generated, it will be unique.

        Args:
            pass_len: The desired length of the password
        Returns:
            random_pass: The generated random password with the given length
        """
        characters = string.ascii_letters + string.digits + '!@#$'
        root_pass_history_list = self.get_password_history()
        while True:
            random_pass = ''.join(secrets.choice(characters) for _ in range(pass_len))
            if random_pass not in root_pass_history_list:
                return random_pass

    def set_root_password(self, server, new_password):
        """
        This method logs in to the server and changes the root password. After changing the root
        password it has sleep time of 1 minute and re-login in to the same server with the new
        credentials to make sure we are able to log in with new credentials and updates the
        database with new credentials. If the password rotation is failed even after 3 attempts
        we will stop the password rotation for that host and will be handled manually.

        Args:
            server: The target host in which we want to log in
            new_password: New generated root password

        Returns:

        """
        ssh = paramiko.SSHClient()
        # ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for attempt in range(1, self.max_attempts + 1):
            try:
                log_msg = f"Started setting Root Password for {server}"
                ssh.connect(hostname=server, username=self.server_username,
                            password=credential_decrypter(self.old_passwords[server]))
                self.file_log(message=log_msg, hostname=server)
                self.db_log(message=log_msg, hostname=server)
                root_pass_change_cmd = self.root_pass_change_cmd
                stdin, stdout, stderr = ssh.exec_command(root_pass_change_cmd)
                stdin.write(f'{new_password}\n')
                stdin.write(f'{new_password}\n')
                stdin.flush()
                stdin.close()
                stdout.channel.set_combine_stderr(True)
                log_msg = (f"Changed the root password for server {server}"
                           f"\nDetails: {stdout.read().decode()}"
                           f"\nSleeping for 1 minute and verify the root password changes are "
                           f"reflected or not")
                self.file_log(message=log_msg, hostname=server)
                self.db_log(message=log_msg, hostname=server)
                # Sleep for 1 min to make sure password changes are reflected
                time.sleep(60)
                if self.verify_server_login(server_name=server):
                    log_msg = f"Successfully changed root password for server {server}"
                    self.file_log(message=log_msg, hostname=server)
                    self.db_log(message=log_msg, hostname=server)
                    self.update_password_to_database(server_name=server)
                    self.store_password_history(server_name=server)
                    self.password_change_success_host_list.append(server)
                else:
                    self.password_change_fail_host_list.append(server)
                break
            except Exception as error:
                if attempt < self.max_attempts:
                    log_msg = (f"Error in changing root password to server {server} "
                               f"(Attempt {attempt}/{self.max_attempts}). Error: {error}"
                               f"\nRetrying in 5 seconds...")
                    self.file_log(message=log_msg, hostname=server)
                    self.db_log(message=log_msg, hostname=server)
                    self.send_alert_mail(hostname=server, error_msg=error)
                    time.sleep(1200)
                else:
                    log_msg = (f"Failed to change root password of server {server} "
                               f"after {self.max_attempts} attempts. Root Password Rotation failed."
                               f"\nError: {error}")
                    self.file_log(message=log_msg, hostname=server)
                    self.db_log(message=log_msg, hostname=server)
                    self.password_change_fail_host_list.append(server)
            finally:
                ssh.close()

    def send_mail(self):
        """
        This method will send email to the recipients defined, regarding the completion of
        Password Rotation and also contains the list of failed hosts

        Returns:

        """
        with open(os.path.join(self.base_dir, _config['smtp']['mail_template']), "r",
                  encoding="utf-8") as template_file:
            email_template = template_file.read()
            table1_rows_html, table2_rows_html = self.generate_table_rows_for_mail()
            body = email_template.format(success_host_rows=table1_rows_html,
                                         failed_host_rows=table2_rows_html)
            sender_mail = _config['smtp']['from_mail']
            recipient_mail = _config['smtp']['to_mail']
            smtp_server = _config['smtp']['hostname']
            subject = _config['smtp']['subject']
            message = MIMEMultipart()
            message['From'] = sender_mail
            message['To'] = ", ".join(recipient_mail)
            message['Subject'] = subject
            message.attach(MIMEText(body, "html"))
            try:
                log_msg = ("Started sending mail to the root users regarding completion of "
                           "Password Rotation")
                self.file_log(message=log_msg, hostname="NA")
                with smtplib.SMTP(smtp_server) as smtpserver:
                    smtpserver.sendmail(sender_mail, recipient_mail, message.as_string())
                log_msg = ("Successfully sent the mail to the root users regarding completion of "
                           "Password Rotation")
                self.file_log(message=log_msg, hostname="NA")
            except Exception as error:
                log_msg = (f"Failed to send mail to the root users regarding completion of "
                           f"Password Rotation"
                           f"\nError - {error}")
                self.file_log(message=log_msg, hostname="NA")

    def generate_table_rows_for_mail(self):
        """
        This method is part of email method which generates tables for mail body

        Returns:
            table1_rows, table2_rows: Tuple which contains the HTML code format of list data
        populated in a table

        """
        table1_rows = ""
        table2_rows = ""
        for i in self.password_change_success_host_list:
            table1_rows += f"<tr><td>{i}</td></tr>"
        for i in self.password_change_fail_host_list:
            table2_rows += f"<tr><td>{i}</td></tr>"
        return table1_rows, table2_rows

    def get_old_password(self):
        """
        This method will get the current root password of all the servers which is stored in
        database

        Returns:
            password_dict: Dictionary which contains the hostname and the current root password
        of that host
        """
        statement = _config['root_password']['select_query']
        try:
            with self.engine.connect() as connection:
                result = connection.execute(text(statement))
                connection.close()
            password_dict = {}
            for row in result:
                password_dict[str(row[0])] = str(row[1])
            return password_dict
        except Exception as error:
            log_msg = (f"Failed to get current root password of the server from database"
                       f"\nError: {error}")
            self.file_log(message=log_msg, hostname="NA")

    def verify_server_login(self, server_name):
        """
        This method will validate whether the root password changes are reflected on the server
        by logging into the server with new generated root password

        Args:
            server_name: The host for which we want to validate

        Returns:

        """
        ssh = paramiko.SSHClient()
        # ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            log_msg = f"Started Validating the new root paasword for {server_name}"
            ssh.connect(hostname=server_name, username=self.server_username,
                        password=self.new_password_generated)
            self.file_log(message=log_msg, hostname=server_name)
            self.db_log(message=log_msg, hostname=server_name)
            return True
        except paramiko.AuthenticationException as error:
            log_msg = (f"Validation Failed for {server_name} while trying to login with new "
                       f"generated root password"
                       f"\nError: {error}")
            self.file_log(message=log_msg, hostname=server_name)
            self.db_log(message=log_msg, hostname=server_name)
            return False

    def store_password_history(self, server_name):
        """
        This method will store the new passwords in the root_pass_history table which is useful
        to check whether the new generated password is already used or not

        Args:
            server_name: The Hostname of the server

        Returns:

        """
        insert_query = _config['password_history']['insert_query']
        current_timestamp = datetime.datetime.now()
        password = self.new_password_generated
        insert_query = insert_query.format(hostname=server_name, password=password,
                                           timestamp=current_timestamp)
        try:
            with self.engine.connect() as connection:
                connection.execute(text(insert_query))
                connection.close()
        except Exception as error:
            log_msg = (f"Failed to store the new root password in password history table"
                       f"\nError: {error}")
            self.file_log(message=log_msg, hostname="NA")

    def get_password_history(self):
        """
        This method makes a select query to the database and get the list of all unique passwords

        Returns:
            password_history_list_decrypted: list of decrypted unique root passwords
        """
        select_query = _config['password_history']['select_query']
        try:
            with self.engine.connect() as connection:
                result = connection.execute(text(select_query))
                connection.close()
            password_history_list_encrypted = []
            for row in result:
                password_history_list_encrypted.append(row[0])
            password_history_list_decrypted = list(
                map(credential_decrypter, password_history_list_encrypted))
            return password_history_list_decrypted
        except Exception as error:
            log_msg = (f"Failed to get the password history of all the hosts from database"
                       f"\nError:{error}")
            self.file_log(message=log_msg, hostname="NA")

    def update_password_to_database(self, server_name):
        """
        This method will update the password in the database once the root password rotation is
        done, and it is validated
        Args:
            server_name: The name of the server for which password has to be updated

        Returns:

        """
        insert_query = _config['root_password']['insert_query']
        current_timestamp = datetime.datetime.now()
        insert_query = insert_query.format(hostname=server_name,
                                           old_password=self.old_passwords[server_name],
                                           new_password=credential_encrypter(
                                               self.new_password_generated),
                                           timestamp=current_timestamp)
        try:
            with self.engine.connect() as connection:
                connection.execute(text(insert_query))
                connection.close()
        except Exception as error:
            log_msg = (f"Failed to update the new password to the database for host {server_name}"
                       f"\nError: {error}")
            self.file_log(message=log_msg, hostname="NA")

    def send_alert_mail(self, hostname, error_msg):
        """
        This method will send an alert mail to the users when the password rotation is failed so
        that the users will take action on the server during the sleep period. This method will
        be called maximum of three times
        Args:
            hostname: The name of the server for which Password Rotation failed
            error_msg: The error message for the server

        Returns:

        """
        with open(os.path.join(self.base_dir, _config['smtp']['alert_mail_template']), "r",
                  encoding="utf-8") as template_file:
            email_template = template_file.read()
            body = email_template.format(host_name=hostname, error=error_msg)
            sender_mail = _config['smtp']['from_mail']
            recipient_mail = _config['smtp']['to_mail']
            smtp_server = _config['smtp']['hostname']
            subject = _config['smtp']['alert_subject']
            message = MIMEMultipart()
            message['From'] = sender_mail
            message['Bcc'] = ", ".join(recipient_mail)
            message['Subject'] = subject
            message.attach(MIMEText(body, "html"))
            try:
                log_msg = "Started sending Alert Mail"
                self.file_log(message=log_msg, hostname=hostname)
                with smtplib.SMTP(smtp_server) as smtpserver:
                    smtpserver.sendmail(sender_mail, recipient_mail, message.as_string())
                log_msg = "Successfully sent the mail regarding Password Failure"
                self.file_log(message=log_msg, hostname=hostname)
            except Exception as error:
                log_msg = (f"Failed to send mail regarding Password Failure"
                           f"\nError: {error}")
                self.file_log(message=log_msg, hostname=hostname)


if __name__ == "__main__":
    rotation_obj = Rotation()
    rotation_obj.run()
