# -*- coding: utf-8 -*-
"""
    flaskext.auth
    ~~~~~~~~~~~~~

    Flask extension for role-based user administration and authentication. 
    Designed to be DB agnostic and still fairly plug-and-play.

    :copyright: (c) 2012 by Lars de Ridder.
    :license: BSD, see LICENSE for more details.
"""

from flaskext.auth.auth import Auth, AuthUser, login, logout, \
        get_current_user_data, login_required, encrypt
from flaskext.auth.permissions import has_permission, permission_required, \
        Role, Permission
