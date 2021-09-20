import sqlite3

from core.logger import logging
from core.constants import USER_TABLE

class DB:
    @staticmethod
    def initialize_db():
        connection = sqlite3.connect('db.sqlite3')
        connection.execute(f'CREATE TABLE {USER_TABLE}(user_id string, username varchar(255), email_id varchar(255), phone varchar(255), password varchar(1023), employee int, failed_logins int, session_token varchar(1023))')
        connection.execute(f'CREATE TABLE account_summary (user_id string, balance real, credit_due real, credit_score real)')
        connection.execute(f'CREATE TABLE account_transactions (user_id string, transaction_type varchar(7), amount real, balance real)')
        connection.commit()
        connection.close()
    
    @staticmethod
    def retrieve(query):
        logging.debug(f'SELECT query {repr(query)}')
        connection = sqlite3.connect('db.sqlite3')
        cursor = connection.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        connection.close()
        return results
        
    @staticmethod
    def modify(query):
        logging.debug(f'MODIFY query {repr(query)}')
        connection = sqlite3.connect('db.sqlite3')
        cursor = connection.cursor()
        cursor.execute(query)
        connection.commit()
        connection.close()
        return True
