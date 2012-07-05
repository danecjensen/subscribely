"""
Module containing functions and classes specific to the permission model.
"""

from flask import current_app
from flaskext.auth.auth import get_current_user_data, not_logged_in

def has_permission(role, resource, action):
    """Function to check if a user has the specified permission."""
    role = current_app.auth.load_role(role)
    return role.has_permission(resource, action) if role else False

def permission_required(resource, action, callback=None):
    """
    Decorator for views that require a certain permission of the logged in 
    user.
    """
    def wrap(func):
        def decorator(*args, **kwargs):
            user_data = get_current_user_data()
            if user_data is None:
                return not_logged_in(callback, *args, **kwargs)
            if not has_permission(user_data.get('role'), resource, action):
                if callback is None:
                    return current_app.auth.not_permitted_callback(*args, **kwargs)
                else:
                    return callback(*args, **kwargs)
                return callback(*args, **kwargs)
            return func(*args, **kwargs)
        return decorator
    return wrap

class Permission(object):
    """
    Permission object, representing actions that can be taken on a resource.
    
    Attributes:

    - resource: A resource is a component on which actions can be performed.
      Examples: post, user, ticket, product, but also post.comment, user.role,
      etc.
    - action: Any action that can be performed on a resource. Names of actions
      should be short and clear. Examples: create, read, update, delete, download,
      list, etc.
    """
    
    def __init__(self, resource, action): 
        self.resource = resource
        self.action = action

    def __eq__(self, other):
        return self.resource == other.resource and self.action == other.action

class Role(object):
    """
    Role object to group users and permissions.

    Attributes:

    - name: The name of the role.
    - permissions: A list of permissions.
    """
    def __init__(self, name, permissions):
        self.name = name
        self.permissions = permissions

    def has_permission(self, resource, action):
        return any([resource == perm.resource and action == perm.action\
                   for perm in self.permissions])

