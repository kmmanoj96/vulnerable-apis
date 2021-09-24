import re
import time
import os

from uuid import uuid4
from flask import Flask, request
from core.logger import logging
from core.db import DB
from core.constants import USER_TABLE
from jwt import encode as jwt_encode, decode as jwt_decode

app = Flask(__name__)
jwt_secret = 'bankbank'
SERVER_ERROR = 'Oops! Something is wrong at our end! Please try again later.'
PASS_CACHE = dict()

if os.getenv('TRANSIENT_DB') is not None:
    logging.info('Recreating DB')
    if os.path.exists('db.sqlite3'):
        os.remove('db.sqlite3')
    DB.initialize_db()

@app.route('/', methods=['GET'])
def welcome():
    return dict(
        application='gullible-bank',
        version='1.0.0',
        status='running'
    )

@app.route('/user', methods=['POST'])
def create_user():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return dict(status='FORBIDDEN', message='missing credentials'), 403
    username = data['username']
    password = data['password']
    pattern = r'^[0-9A-Za-z]+$'
    if not re.match(pattern, username) or not re.match(pattern, password):
        logging.error(f'Bad pattern')
        return dict(status='FORBIDDEN', message=f'username and password should match the pattern {pattern}'), 403

    try:
        users_query = f"SELECT * FROM {USER_TABLE} WHERE username = '{username}'"
        users = DB.retrieve(users_query)
        if len(users) > 0:
            logging.error(f'No user having username={username}')
            return dict(status='FORBIDDEN', message=f'Username already taken!'), 403
        user_id = uuid4()
        insert_user = f"INSERT INTO {USER_TABLE} values('{user_id}', '{username}', '', '', '{password}', 0, 0, '')"
        DB.modify(insert_user)
        insert_acc_sum = f"INSERT INTO account_summary values('{user_id}', 0, 0)"
        DB.modify(insert_acc_sum)
        user = dict()
        user['user_id'] = user_id
        user['username'] = username
        return dict(status='OK', response=user), 200
    except Exception as e:
        logging.error(str(e))
        return dict(status='SERVER ERROR', response=SERVER_ERROR), 500

# API2:2019 Broken Authentication
def get_info_from_token(api_token):
    if not api_token:
        return None
    try:
        decoded = jwt_decode(api_token, jwt_secret, algorithms=["HS256"])
        if decoded['expires'] < time.time():
            logging.warning("Token expired")
            return None
        for key, value in decoded.items():
            if not re.match(r'^[0-9A-Za-z_]+$', key) or not re.match(r'^[0-9A-Za-z-.]+$', str(value)): 
                logging.error('Bad pattern in token')
                raise Exception('Bad pattern')
        session_query = f"SELECT * FROM {USER_TABLE} WHERE session_token = '{api_token}'"
        records = DB.retrieve(session_query)
        return decoded if len(records) > 0 else None
    except Exception as e:
        logging.error(str(e))
        return None

@app.route('/user', methods=['GET'])
def get_user_info():
    session_token = request.headers.get('X-API-key')
    user_info = get_info_from_token(session_token)
    if not user_info:
        logging.warning(f'No User info')
        return dict(status='FORBIDDEN', message=f'Unauthenticated!'), 403
    user_record_query = f"SELECT * FROM {USER_TABLE} WHERE user_id = '{user_info['user_id']}'" 
    user = DB.retrieve(user_record_query)[0]
    userd = dict()
    userd['user_id'], userd['username'], userd['email_id'], userd['phone_number'], _, userd['employee'], userd['failed_logins'], _ = user
    return dict(status='OK', response=userd)

# API6:2019 Mass assignment
@app.route('/user', methods=['PUT'])
def update_user_info():
    session_token = request.headers.get('X-API-key')
    user_info = get_info_from_token(session_token)
    if not user_info:
        logging.warning(f'No User info')
        return dict(status='FORBIDDEN', message=f'Unauthenticated!'), 403
    updatables = request.json
    if not updatables:
        logging.warning(f'No updatable User info')
        return dict(status='FORBIDDEN', message=f'Missing information'), 403
    updates = []
    for key, value in updatables.items():
        if not re.match(r'^[0-9A-Za-z@+. ]+$', str(value)): continue
        if type(value) in [int, float]:
            updates.append(f"{key} = {value}")
        else:
            updates.append(f"{key} = '{value}'")
    if len(updates) > 0:
        try:
            update_query = f"UPDATE {USER_TABLE} SET {', '.join(updates)} WHERE user_id = '{user_info['user_id']}'"
            DB.modify(update_query)
        except Exception as e:
            logging.error(str(e))
    user_record_query = f"SELECT * FROM {USER_TABLE} WHERE user_id = '{user_info['user_id']}'" 
    user = DB.retrieve(user_record_query)[0]
    userd = dict()
    userd['user_id'], userd['username'], userd['email_id'], userd['phone_number'], _, userd['employee'], userd['failed_logins'], _ = user
    return dict(status='OK', response=userd)
    
@app.route('/user/login', methods=['POST'])
def login():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return dict(status='FORBIDDEN', message='missing credentials'), 403
    username = data['username']
    password = data['password']
    pattern = r'^[0-9A-Za-z]+$'
    if not re.match(pattern, username) or not re.match(pattern, password):
        logging.error(f'Bad pattern')
        return dict(status='FORBIDDEN', message=f'Authentication Failed!'), 403
    
    try:
        users_query = f"SELECT * FROM {USER_TABLE} WHERE username = '{username}'"
        users = DB.retrieve(users_query)
        if len(users) == 0:
            return dict(status='FORBIDDEN', message=f'Authentication Failed!'), 403
        user = users[0]
        if user[6] + 1 > 3:
            return dict(status='FORBIDDEN', message=f'User locked out! Try again later'), 403
        if user[4] != password:
            update_loginfail = f"UPDATE {USER_TABLE} SET failed_logins = {user[6]+1} WHERE username = '{username}'"
            DB.modify(update_loginfail)
            return dict(status='FORBIDDEN', message=f'Authentication Failed!'), 403
        
        userd = dict()
        userd['user_id'] = user[0]
        userd['username'] = user[1]
        userd['expires'] = (time.time() + 3600)
        if int(user[5]) == 1:
            logging.info(f'Is an employee')
            userd['aRe_yOu_An_EmPlOyEe'] = True
        else:
            logging.info(f'Is NOT an employee')
        userd['session_token'] = jwt_encode(userd, jwt_secret, algorithm='HS256')

        update_session = f"UPDATE {USER_TABLE} SET failed_logins = 0, session_token = '{userd['session_token']}' WHERE username = '{username}'"
        DB.modify(update_session)
        return dict(status='OK', response=userd), 200
    except Exception as e:
        logging.error(e)
        return dict(status='SERVER ERROR', response=SERVER_ERROR), 500

# API4:2019 Lack of resources and rate limiting
@app.route('/user/change-password', methods=['POST'])
def change_password():
    global PASS_CACHE
    session_token = request.headers.get('X-API-key')
    user_info = get_info_from_token(session_token)
    if not user_info:
        return dict(status='FORBIDDEN', message=f'Unauthenticated!'), 403
    
    data = request.json
    if not data or 'username' not in data or 'old_password' not in data or 'new_password' not in data:
        return dict(status='FORBIDDEN', message='missing credentials'), 403
    username = data['username']
    old_pass = data['old_password']
    new_pass = data['new_password']
    pattern = r'^[0-9A-Za-z]+$'
    if not re.match(pattern, username) or not re.match(pattern, old_pass) or not re.match(pattern, new_pass):
        logging.info(f'Bad pattern')
        return dict(status='FORBIDDEN', message=f'username and passwords should match the pattern {pattern}'), 403

    old_pass_val = None
    logging.debug(username + str(PASS_CACHE))
    if username in PASS_CACHE:
        logging.info(f'using cache')
        old_pass_val = PASS_CACHE[username]
    else:
        logging.info(f'NOT using cache')
        pass_query = f"SELECT password FROM {USER_TABLE} WHERE username = '{username}'"
        old_pass_val_record = DB.retrieve(pass_query)
        if len(old_pass_val_record) == 0:
            return dict(status='FORBIDDEN', message=f'Invalid username'), 403
        old_pass_val = old_pass_val_record[0][0]
        PASS_CACHE[username] = old_pass_val
    
    logging.debug(PASS_CACHE)
    
    if old_pass != old_pass_val:
        return dict(status='FORBIDDEN', message=f'Wrong old password'), 403
    
    try:
        update_pass = f"UPDATE {USER_TABLE} SET password = '{new_pass}' WHERE username = '{username}'"
        DB.modify(update_pass)
        PASS_CACHE[username] = new_pass
        logging.debug(PASS_CACHE)
        update_loginfail = f"UPDATE {USER_TABLE} SET failed_logins = 0 WHERE username = '{username}'"
        DB.modify(update_loginfail)
        return dict(status='OK', message=f'Password updated successfully!'), 200
    except Exception as e:
        logging.error(str(e))
        return dict(status='SERVER ERROR', response=SERVER_ERROR), 500

@app.route('/user/logout', methods=['GET'])
def logout():
    session_token = request.headers.get('X-API-key')
    user_info = get_info_from_token(session_token)
    if not user_info:
        return dict(status='FORBIDDEN', message=f'Unauthenticated!'), 403
    try:
        update_session = f"UPDATE {USER_TABLE} SET session_token = '' WHERE user_id = '{user_info['user_id']}'"
        DB.modify(update_session)
        return dict(status='OK', response='Successfully logged out!'), 200
    except Exception as e:
        logging.error(str(e))
        return dict(status='SERVER ERROR', response=SERVER_ERROR), 500

# API1:2019 Broken object level authorization
@app.route('/account/<user_id>/summary', methods=['GET'])
def get_account_summary(user_id):
    session_token = request.headers.get('X-API-key')
    user_info = get_info_from_token(session_token)
    if not user_info:
        return dict(status='FORBIDDEN', message=f'Unauthenticated!'), 403
    if not re.match(r'^[0-9A-Za-z-]+$', user_id):
        return dict(status='FORBIDDEN', message=f'Bad pattern User ID!'), 403
    try:
        summary_statement = f"SELECT * FROM account_summary WHERE user_id = '{user_id}'"
        account_summary = DB.retrieve(summary_statement)
        response = dict()
        response['user_id'], response['balance'], response['last_transaction'] = account_summary[0]
        return dict(status='OK', response=response), 200
    except Exception as e:
        logging.error(str(e))
        return dict(status='SERVER ERROR', response=SERVER_ERROR), 500

# API7:2019 Security Misconfiguration
# API8:2019 Injection
@app.route('/account/transactions', methods=['GET'])
def get_account_transactions():
    session_token = request.headers.get('X-API-key')
    user_info = get_info_from_token(session_token)
    if not user_info:
        return dict(status='FORBIDDEN', message=f'Unauthenticated!'), 403
    try:
        limit = request.args.get('limit')
        limit = int(limit) if limit else 10

        search_string = request.args.get('filter')
        search_string = search_string if search_string else ''
        transactions_statement = f"SELECT * FROM account_transactions WHERE user_id = '{user_info['user_id']}' AND transaction_party LIKE '%{search_string}%' ORDER BY transaction_time DESC LIMIT {limit};"
        transactions = DB.retrieve(transactions_statement)
        response = list()
        for transaction in transactions:
            t = dict()
            t['user_id'], t['transaction_time'], t['transaction_party'], t['transaction_type'], t['transaction_amount'], t['balance'] = transaction
            response.append(t)
        return dict(status='OK', response=response), 200
    except Exception as e:
        logging.error(str(e))
        # TODO: CORS allow all headers
        return dict(status='SERVER ERROR', response=str(e)), 500

# API3:2019 Excessive data exposure 
@app.route('/people/customers', methods=['GET'])
def get_customers():
    try:
        customers_query = f"SELECT * FROM {USER_TABLE} WHERE employee = 0"
        customers = DB.retrieve(customers_query)
        result = list()
        for customer in customers:
            cd = dict()
            cd['user_id'], cd['username'], cd['email_id'], cd['phone'] = customer[:4]
            result.append(cd)
        return dict(status='OK', response=result), 200
    except Exception as e:
        logging.error(str(e))
        return dict(status='SERVER ERROR', response=SERVER_ERROR), 500

# HIDDEN FROM COLLECTIONS
# API5:2019 Broken function level authorization
@app.route('/people/employees', methods=['GET'])
def get_admins():
    try:
        employees_query = f"SELECT * FROM {USER_TABLE} WHERE employee = 1"
        employees = DB.retrieve(employees_query)
        result = list()
        for employee in employees:
            ed = dict()
            ed['user_id'], ed['username'], ed['email_id'], ed['phone'] = employee[:4]
            result.append(ed)
        return dict(status='OK', response=result), 200
    except Exception as e:
        logging.error(str(e))
        return dict(status='SERVER ERROR', response=SERVER_ERROR), 500

@app.route('/admin/credit', methods=['POST'])
def admin_credit():
    session_token = request.headers.get('X-API-key')
    user_info = get_info_from_token(session_token)
    if not user_info:
        return dict(status='FORBIDDEN', message=f'Unauthenticated!'), 403
    
    if 'aRe_yOu_An_EmPlOyEe' not in user_info or not (user_info['aRe_yOu_An_EmPlOyEe'] == True):
        return dict(status='FORBIDDEN', message='You are not an admin!'), 403

    data = request.json
    if not data or 'user_id' not in data or 'transaction_party' not in data or 'transaction_amount' not in data:
        return dict(status='FORBIDDEN', message='missing information'), 403
    try:
        user_id = data['user_id']
        tr_time = time.time() 
        tr_party = data['transaction_party']
        tr_amount = max(0, float(data['transaction_amount']))

        pattern = r'^[0-9A-Za-z- ]+$'
        if not re.match(pattern, user_id) or not re.match(pattern, tr_party):
            return dict(status='FORBIDDEN', message=f'Bad pattern for user ID or transaction party. Should match {pattern}'), 403

        get_balance_query = f"SELECT balance FROM account_summary WHERE user_id = '{user_id}'"
        balance_record = DB.retrieve(get_balance_query)
        if len(balance_record) == 0:
            return dict(status='FORBIDDEN', message=f'Invalid User ID!'), 403
        balance = balance_record[0][0]
        balance += tr_amount

        add_tr_query = f"INSERT INTO account_transactions values('{user_id}', {tr_time}, '{tr_party}', 'credit', {tr_amount}, {balance})"
        DB.modify(add_tr_query)

        update_balance = f"UPDATE account_summary SET balance = {balance}, last_transaction = {tr_time} WHERE user_id = '{user_id}'"
        DB.modify(update_balance)
        
        return dict(status='OK', response='Amount credited'), 200

    except Exception as e:
        logging.error(str(e))
        return dict(status='SERVER ERROR', response=SERVER_ERROR), 500

@app.route('/admin/debit', methods=['POST'])
def admin_debit():
    session_token = request.headers.get('X-API-key')
    user_info = get_info_from_token(session_token)
    if not user_info:
        return dict(status='FORBIDDEN', message=f'Unauthenticated!'), 403
    
    if 'aRe_yOu_An_EmPlOyEe' not in user_info or not (user_info['aRe_yOu_An_EmPlOyEe'] == True):
        return dict(status='FORBIDDEN', message='You are not an admin!'), 403

    data = request.json
    if not data or 'user_id' not in data or 'transaction_party' not in data or 'transaction_amount' not in data:
        return dict(status='FORBIDDEN', message='missing information'), 403

    try:
        user_id = data['user_id']
        tr_time = time.time() 
        tr_party = data['transaction_party']
        tr_amount = max(0, float(data['transaction_amount']))

        pattern = r'^[0-9A-Za-z- ]+$'
        if not re.match(pattern, user_id) or not re.match(pattern, tr_party):
            return dict(status='FORBIDDEN', message=f'Bad pattern for user ID or transaction party. Should match {pattern}'), 403

        get_balance_query = f"SELECT balance FROM account_summary WHERE user_id = '{user_id}'"
        balance_record = DB.retrieve(get_balance_query)
        if len(balance_record) == 0:
            return dict(status='FORBIDDEN', message=f'Invalid User ID!'), 403
        balance = balance_record[0][0]
        if balance < tr_amount:
            return dict(status='FORBIDDEN', message=f'Insufficient Balance!'), 403
        balance -= tr_amount

        add_tr_query = f"INSERT INTO account_transactions values('{user_id}', {tr_time}, '{tr_party}', 'debit', {tr_amount}, {balance})"
        DB.modify(add_tr_query)

        update_balance = f"UPDATE account_summary SET balance = {balance}, last_transaction = {tr_time} WHERE user_id = '{user_id}'"
        DB.modify(update_balance)
        
        return dict(status='OK', response='Amount debited'), 200

    except Exception as e:
        logging.error(str(e))
        return dict(status='SERVER ERROR', response=SERVER_ERROR), 500


app.run(debug=True, host='0.0.0.0')