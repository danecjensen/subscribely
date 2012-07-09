"""
Module to provide plug-and-play authentication support for Google App Engine
using flask-auth.
"""

from google.appengine.ext import db
from flaskext.auth import AuthUser

class User(db.Model, AuthUser):
    """
    Implementation of User for persistence in Google's App Engine datastore.
    """
    username = db.EmailProperty()
    name = db.StringProperty()
    password = db.StringProperty()
    stripe_customer_id = db.StringProperty()
    salt = db.StringProperty()
    role = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    modified = db.DateTimeProperty(auto_now=True)

    def __init__(self, *args, **kwargs):
        kwargs['key_name'] = kwargs.get('username')
        super(User, self).__init__(*args, **kwargs)
        password = kwargs.get('password')
        if password is not None and not self.has_key():
            # Initialize and encrypt password before first save.
            self.set_and_encrypt_password(password)

    @classmethod
    def get_by_username(cls, username):
        return cls.get_by_key_name(username)