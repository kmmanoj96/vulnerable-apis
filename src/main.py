import re
import time

from uuid import uuid4
from flask import Flask, request
from hashlib import sha256
from core.logger import logging
from core.db import DB
from core.constants import USER_TABLE
from jwt import encode as jwt_encode, decode as jwt_decode

app = Flask(__name__)
jwt_secret = 'JWT_t0p_s3cr3t_c0d3'
SERVER_ERROR = 'Oops! Something is wrong at our end! Please try again later.'

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
    if 'username' not in data or 'password' not in data:
        return dict(status='FORBIDDEN', message='missing credentials'), 403
    username = data['username']
    password = data['password']
    pattern = r'^[0-9A-Za-z]+$'
    if not re.match(pattern, username) or not re.match(pattern, password):
        return dict(status='FORBIDDEN', message=f'username and password should match the pattern {pattern}'), 403

    try:
        users_query = f"SELECT * FROM {USER_TABLE} where username = '{username}'"
        users = DB.retrieve(users_query)
        if len(users) > 0:
            return dict(status='FORBIDDEN', message=f'Username already taken!'), 403
        user_id = uuid4()
        insert_user = f"INSERT INTO {USER_TABLE} values('{user_id}', '{username}', '', '', '{sha256(password.encode()).hexdigest()}', 0, 0, '')"
        DB.modify(insert_user)
        user = dict()
        user['user_id'] = user_id
        user['username'] = username
        return dict(status='OK', response=user), 200
    except Exception as e:
        logging.error(str(e))
        return dict(status='SERVER ERROR', response=SERVER_ERROR), 500

def get_info_from_token(api_token):
    if not api_token:
        return None
    try:
        decoded = jwt_decode(api_token, options=dict(verify_signature=False))
        if decoded['expires'] < time.time():
            return None
        session_query = f"SELECT * FROM {USER_TABLE} where session_token = '{api_token}'"
        records = DB.retrieve(session_query)
        return decoded if len(records) > 0 else None
    except:
        return None

@app.route('/user', methods=['GET'])
def get_user_info():
    user_info = get_info_from_token(request.headers.get('X-API-key'))
    if not user_info:
        return dict(status='FORBIDDEN', message=f'Unauthenticated!'), 403
    user_record_query = f"SELECT * FROM {USER_TABLE} WHERE user_id = '{user_info['user_id']}'" 
    user = DB.retrieve(user_record_query)[0]
    userd = dict()
    userd['user_id'], userd['username'], userd['email_id'], userd['phone_number'], _, userd['employee'], userd['failed_logins'], _ = user
    return dict(status='OK', response=userd)

@app.route('/user', methods=['PUT'])
# API6:2019 Mass assignment
def update_user_info():
    user_info = get_info_from_token(request.headers.get('X-API-key'))
    if not user_info:
        return dict(status='FORBIDDEN', message=f'Unauthenticated!'), 403
    updatables = request.json
    for key, value in updatables.items():
        try:
            if not re.match(r'^[0-9A-Za-z@+. ]+$', str(value)): continue
            if type(value) in [int, float]:
                update_query = f"UPDATE {USER_TABLE} SET {key} = {value} WHERE user_id = '{user_info['user_id']}'"        
            else:
                update_query = f"UPDATE {USER_TABLE} SET {key} = '{value}' WHERE user_id = '{user_info['user_id']}'"
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
    db = DB()
    data = request.json
    if 'username' not in data or 'password' not in data:
        return dict(status='FORBIDDEN', message='missing credentials'), 403
    username = data['username']
    password = data['password']
    pattern = r'^[0-9A-Za-z]+$'
    if not re.match(pattern, username) or not re.match(pattern, password):
        return dict(status='FORBIDDEN', message=f'Authentication Failed!'), 403
    
    try:
        users_query = f"SELECT * FROM {USER_TABLE} where username = '{username}'"
        users = db.retrieve(users_query)
        if len(users) == 0:
            return dict(status='FORBIDDEN', message=f'Authentication Failed!'), 403
        user = users[0]
        if user[4] != sha256(password.encode()).hexdigest():
            if user[6] + 1 > 10:
                return dict(status='FORBIDDEN', message=f'User locked out! Try again later'), 403
            update_loginfail = f"UPDATE {USER_TABLE} SET failed_logins = {user[6]+1} where username = '{username}'"
            db.modify(update_loginfail)
            return dict(status='FORBIDDEN', message=f'Authentication Failed!'), 403
        
        userd = dict()
        userd['user_id'] = user[0]
        userd['username'] = user[1]
        userd['expires'] = (time.time() + 300)
        userd['session_token'] = jwt_encode(userd, jwt_secret, algorithm='HS256')

        update_session = f"UPDATE {USER_TABLE} SET failed_logins = 0, session_token = '{userd['session_token']}' where username = '{username}'"
        db.modify(update_session)
        return dict(status='OK', response=userd), 200
    except Exception as e:
        logging.error(e)
        return dict(status='SERVER ERROR', response=SERVER_ERROR), 500

@app.route('/user/change-password', methods=['POST'])
# API4:2019 Lack of resources and rate limiting
def change_password():
    pass

@app.route('/user/logout', methods=['GET'])
def logout():
    session_token = request.headers.get('X-API-key')
    user_info = get_info_from_token(session_token)
    if not user_info:
        return dict(status='FORBIDDEN', message=f'Unauthenticated!'), 403
    try:
        update_session = f"UPDATE {USER_TABLE} SET session_token = '' where username = '{user_info['username']}'"
        DB.modify(update_session)
        return dict(status='OK', response='Successfully logged out!'), 200
    except Exception as e:
        logging.error(str(e))
        return dict(status='SERVER ERROR', response=SERVER_ERROR), 500

@app.route('/account/summary', methods=['GET'])
def account_summary():
    pass

@app.route('/account/transactions', methods=['GET'])
def account_transactions():
    pass

@app.route('/people/customers', methods=['GET'])
# API3:2019 Excessive data exposure 
def get_customers():
    session_token = request.headers.get('X-API-key')
    user_info = get_info_from_token(session_token)
    if not user_info:
        return dict(status='FORBIDDEN', message=f'Unauthenticated!'), 403
    customers_query = f"SELECT * FROM {USER_TABLE} where employee = 0"
    customers = DB.retrieve(customers_query)
    result = list()
    for customer in customers:
        cd = dict()
        cd['user_id'], cd['username'], cd['email_id'], cd['phone'] = customer[:4]
        result.append(cd)
    return dict(status='OK', response=result), 200

# HIDDEN FROM COLLECTIONS
@app.route('/people/employees', methods=['GET'])
# API5:2019 Broken function level authorization
def get_admins():
    session_token = request.headers.get('X-API-key')
    user_info = get_info_from_token(session_token)
    if not user_info:
        return dict(status='FORBIDDEN', message=f'Unauthenticated!'), 403
    employees_query = f"SELECT * FROM {USER_TABLE} where employee = 1"
    employees = DB.retrieve(employees_query)
    result = list()
    for employee in employees:
        ed = dict()
        ed['user_id'], ed['username'], ed['email_id'], ed['phone'] = employee[:4]
        result.append(ed)
    return dict(status='OK', response=result), 200

@app.route('/admin/credit', methods=['POST'])
def admin_credit():
    pass

@app.route('/admin/debit', methods=['POST'])
def admin_debit():
    pass


app.run(debug=True)