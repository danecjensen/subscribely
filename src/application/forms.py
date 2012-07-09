"""
forms.py

Web forms based on Flask-WTForms

See: http://flask.pocoo.org/docs/patterns/wtforms/
     http://wtforms.simplecodes.com/

"""

from flaskext import wtf
from flaskext.wtf import validators

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

class AddressForm(wtf.Form):
    name = wtf.TextField('Name')
    address1 = wtf.TextField('Address')
    address2 = wtf.TextField('Address 2')
    city = wtf.TextField('City')
    state = wtf.TextField('State')
    zipcode = wtf.TextField('Zipcode')
    country = wtf.TextField('Country')

class CreditCardForm(wtf.Form):
    number = wtf.TextField('Credit Card Number')
    exp_month = wtf.SelectField('', choices=[('1', '1'), ('2', '2'), ('3', '3'), ('4', '4'), ('5', '5'), ('6', '6'), ('7', '7'), ('8', '8'), ('9', '9'), ('10', '10'), ('11', '11'), ('12', '12')])
    exp_year = wtf.SelectField('',  choices=[('2012', '2012'), ('2013', '2013'), ('2014', '2014'), ('2015', '2015'), ('2016', '2016'), ('2017', '2017'), ('2018', '2018')])
    cvc = wtf.TextField('CVC')

class StripeSubscriptionForm(AddressForm):
    stripeToken = wtf.HiddenField()

class SubscriptionForm(AddressForm, CreditCardForm):
    pass


