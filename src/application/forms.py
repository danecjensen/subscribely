"""
forms.py

Web forms based on Flask-WTForms

See: http://flask.pocoo.org/docs/patterns/wtforms/
     http://wtforms.simplecodes.com/

"""

from flaskext import wtf
from flaskext.wtf import validators


class ExampleForm(wtf.Form):
    example_name = wtf.TextField('Name', validators=[validators.Required()])
    example_description = wtf.TextAreaField('Description', validators=[validators.Required()])


class RegistrationForm(wtf.Form):
    email = wtf.TextField('Email Address', [validators.Required()])
    password = wtf.PasswordField('New Password', [
        validators.Required(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = wtf.PasswordField('Repeat Password')


class LoginForm(wtf.Form):
	email = wtf.TextField('Email Address', [validators.Required()])
	password = wtf.PasswordField('Password', [validators.Required()])