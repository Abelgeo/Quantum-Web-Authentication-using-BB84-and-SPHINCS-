from auth_utils import verify_signature

def authenticate_user(username, password, user_data):
    """
    Authenticates the user by verifying their signature and password.
    """
    if username in user_data:
        public_key = user_data[username]['public_key']
        if verify_signature(password, public_key):
            return True
        else:
            return False
    return False
