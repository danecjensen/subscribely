"""
Base module of the extension. Contains basic functions, the Auth object and the
AuthUser base class.
"""

import time, hashlib, datetime
from functools import partial, wraps
from flask import session, abort, current_app, redirect, url_for

DEFAULT_HASH_ALGORITHM = hashlib.sha1

DEFAULT_USER_TIMEOUT = 3600

SESSION_USER_KEY = 'auth_user'
SESSION_LOGIN_KEY = 'auth_login'

def _default_not_authorized(*args, **kwargs):
    return abort(401)

def _redirect_to_login(login_url_name):
    return redirect(url_for(login_url_name))

class Auth(object):
    """
    Extension initialization object containing settings for the extension.
    
    Supported settings:

    - login_url_name: Name of the URL that is used for login. It's used in
      the not_logged_in_callback if provided in the constructor.
    - not_logged_in_callback: Function to call when a user accesses a page
      without being logged in. Normally used to redirect to the login page.
      If a login_url_name is provided, it will by default redirect to that
      url. Otherwise, the default is abort(401).
    - not_permitted_callback: Function to call when a user tries to access
      a page for which he doesn't have the permission. Default: abort(401).
    - hash_algorithm: Algorithm from the hashlib library used for password
      encryption. Default: sha1.
    - user_timeout: Timeout (in seconds) after which the sesion of the user
      expires. Default: 3600. A timeout of 0 means it will never expire.
    - load_role: Function to load a role. Is called with user.role as only
      parameter.
    """

    def __init__(self, app=None, login_url_name=None):
        if login_url_name is None:
            self.not_logged_in_callback = _default_not_authorized
        else:
            self.not_logged_in_callback = partial(_redirect_to_login,
                                                  login_url_name)
        self.not_permitted_callback = _default_not_authorized
        self.hash_algorithm = DEFAULT_HASH_ALGORITHM
        self.user_timeout = DEFAULT_USER_TIMEOUT
        self.load_role = lambda _: None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.auth = self
        
class AuthUser(object):
    """
    Baseclass for a user model. Contains a few convenience methods.

    Attributes:

    - username: Username of the user.
    - password: Password of the user. By default not encrypted. The 
      set_and_encrypt_password() method sets and encrypts the password.
    - salt: Salt used for the encrytion of the password.
    - role: Role of this user.  """

    role = None

    def __init__(self, username=None, password=None, salt=None, role=None):
        self.username = username
        # Storing password unmodified. Encryption of the password should 
        # happen explicitly.
        self.password = password
        self.salt = salt
        self.role = role

    def set_and_encrypt_password(self, password, salt=str(int(time.time()))):
        """
        Encrypts and sets the password. If no salt is provided, a new
        one is generated.
        """
        self.salt = salt
        self.password = encrypt(password, self.salt)

    def authenticate(self, password):
        """
        Attempts to verify the password and log the user in. Returns true if 
        succesful.
        """
        if self.password == encrypt(password, self.salt):
            login(self)
            return True
        return False

    def __eq__(self, other):
        return self.username == getattr(other, 'username', None)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __getstate__(self):
        return self.__dict__

    @classmethod
    def load_current_user(cls, apply_timeout=True):
        """
        Load current user based on the result of get_current_user_data().
        """
        data = get_current_user_data(apply_timeout)
        if not data:
            return None
        user = cls()
        user.__dict__ = data
        return user

    def is_logged_in(self):
        user_data = get_current_user_data()
        return user_data is not None and user_data.get('username') == self.username

def encrypt(password, salt=None, hash_algorithm=None):
    """Encrypts a password based on the hashing algorithm."""
    to_encrypt = password
    if salt is not None:
        to_encrypt += salt
    if hash_algorithm is not None:
        return hash_algorithm(to_encrypt).hexdigest()
    return current_app.auth.hash_algorithm(to_encrypt).hexdigest()

def login(user):
    """
    Logs the user in. Note that NO AUTHENTICATION is done by this function. If
    you want to authenticate a user, use the AuthUser.authenticate() method.
    """
    session[SESSION_USER_KEY] = user.__getstate__()
    session[SESSION_LOGIN_KEY] = datetime.datetime.utcnow()

def logout():
    """Logs the currently logged in user out and returns the user data."""
    session.pop(SESSION_LOGIN_KEY, None)
    return session.pop(SESSION_USER_KEY, None)
    
def get_current_user_data(apply_timeout=True):
    """ 
    Returns the data of the current user (user.__dict__) if there is a
    current user and he didn't time out yet. If timeout should be ignored,
    provide apply_timeout=False.  
    """
    user_data = session.get(SESSION_USER_KEY, None)
    if user_data is None:
        return None 
    if not apply_timeout:
        return user_data
    login_datetime = session[SESSION_LOGIN_KEY]
    now = datetime.datetime.utcnow()
    user_timeout = current_app.auth.user_timeout
    if user_timeout > 0 and now - login_datetime > \
       datetime.timedelta(seconds=user_timeout):
        logout()
        return None
    return user_data

def not_logged_in(callback, *args, **kwargs):
    """
    Executes not logged in callback. Not for external use.
    """
    if callback is None:
        return current_app.auth.not_logged_in_callback(*args, **kwargs)
    else:
        return callback(*args, **kwargs)

def login_required(func, callback=None):
    """
    Decorator for views that require login. Callback can be specified to
    override the default callback on the auth object.
    """
    @wraps(func)
    def decorator(*args, **kwargs):
        if get_current_user_data() is None:
            return not_logged_in(callback, *args, **kwargs)
        return func(*args, **kwargs)
    return decorator