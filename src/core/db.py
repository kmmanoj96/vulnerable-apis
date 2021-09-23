import sqlite3

from core.logger import logging
from core.constants import USER_TABLE

class DB:
    @staticmethod
    def initialize_db():
        connection = sqlite3.connect('db.sqlite3')
        logging.info(f'User table is not {USER_TABLE}')
        connection.execute(f'CREATE TABLE {USER_TABLE} (user_id string, username varchar(255), email_id varchar(255), phone varchar(255), password varchar(1023), employee int, failed_logins int, session_token varchar(1023))')
        connection.execute(f'CREATE TABLE account_summary (user_id string, balance real, last_transaction real)')
        connection.execute(f'CREATE TABLE account_transactions (user_id string, transaction_time real, transaction_party varchar(255), transaction_type varchar(7), transaction_amount real, balance real)')
        connection.execute(f'''INSERT INTO {USER_TABLE} VALUES
        ('1fd7cd4e-9925-4abf-a09d-7d0f05acb86e', 'theFounder', 'theFounder@gulbank.com', '+91 1234567890', 'th3F0und3rspassw0rd', 1, 0, ''),
        ('2e0b0a82-e11d-4c62-87d2-901813d684e1', 'theCEO', 'theCEO@gulbank.com', '+91 9876543210', 'th3c30sp455', 1, 0, ''), 
        ('1ce7cb77-e991-42db-84a2-742c7e3dce16', 'user001', 'user001@email.com', '', 'userpass01isverycomplex', 0, 0, ''), 
        ('f6938f49-d227-4745-a711-1d0616a9d6cd', 'user002', 'user002@mailid.com', '+1 1234543211', 'userpass02isalsocomplex', 0, 0, ''), 
        ('01fb8943-ea83-4d23-94e0-80209d5a893d', 'adam', '', '', 'account', 0, 0, '')
        ''')
        connection.execute(f'''INSERT INTO account_summary VALUES
        ('1ce7cb77-e991-42db-84a2-742c7e3dce16', 187236.35, 1632204630.2189791), 
        ('f6938f49-d227-4745-a711-1d0616a9d6cd', 8182.81, 163228189462.7294726), 
        ('01fb8943-ea83-4d23-94e0-80209d5a893d', 0.23, 163228463745.9283746)
        ''')
        connection.execute(f'''INSERT INTO account_transactions VALUES
        ('1ce7cb77-e991-42db-84a2-742c7e3dce16', 1632204630.2189791, 'someone', 'credit', 187000.35, 187236.35),
        ('1ce7cb77-e991-42db-84a2-742c7e3dce16', 1632104630.8472627, 'heere', 'debit', 500.00, 236.00),
        ('1ce7cb77-e991-42db-84a2-742c7e3dce16', 1632004630.3857382, 'theiare', 'credit', 736.00, 736.00),
        ('f6938f49-d227-4745-a711-1d0616a9d6cd', 163228189462.7294726, 'somebody', 'debit', 2000, 8182.81),
        ('f6938f49-d227-4745-a711-1d0616a9d6cd', 163228188273.8764738, 'from here', 'credit', 4182.81, 10182.81),
        ('f6938f49-d227-4745-a711-1d0616a9d6cd', 163228173857.2948857, 'payed', 'credit', 4000, 6000.00),
        ('f6938f49-d227-4745-a711-1d0616a9d6cd', 163228171857.9284723, 'from there', 'credit', 2000, 2000.00),
        ('01fb8943-ea83-4d23-94e0-80209d5a893d', 163228463745.9283746, 'from nowhere', 'debit', 20000, 0.23),
        ('01fb8943-ea83-4d23-94e0-80209d5a893d', 163219281726.8172645, 'initially', 'credit', 20000.23, 20000.23)
        ''')
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
