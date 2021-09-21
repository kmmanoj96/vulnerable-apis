import os

USER_TABLE = f'users_{os.getenv("USER_SALT")}' if os.getenv("USER_SALT") else 'users_gqviprviveefkttsfbasfrpsvzutawrb'
