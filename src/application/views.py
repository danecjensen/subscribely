"""
views.py

URL route handlers

Note that any handler params must match the URL route params.
For example the *say_hello* handler, handling the URL route '/hello/<username>',
  must be passed *username* as the argument.

"""

from application import app

from google.appengine.runtime.apiproxy_errors import CapabilityDisabledError
from google.appengine.api import mail

from flask import render_template, render_template_string, request, flash, g, url_for, redirect, session

from models import MailingAddress
from decorators import admin_required
from forms import RegistrationForm, LoginForm, StripeSubscriptionForm, AddressForm
from flaskext.auth import Auth, login, logout, login_required
from flaskext.auth.models.gae import User
from flaskext.oauth import OAuth
import stripe

FACEBOOK_APP_ID = '445106095520759'
FACEBOOK_APP_SECRET = 'b89cacf4ea4fdb08fed9f1d2f71a98a6'
STRIPE_SECRET = 'oqfhEnnahozCOBvY0ZtxRNs9Arb4GrXG'
STRIPE_PUB_KEY = 'pk_V5tvgwqsXfUlNrKwYrhE9SlqzHRLO'


Auth(app, login_url_name='login_view')
oauth = OAuth()

facebook = oauth.remote_app('facebook',
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key=FACEBOOK_APP_ID,
    consumer_secret=FACEBOOK_APP_SECRET,
    request_token_params={'scope': 'email'}
)

@app.context_processor
def inject_user():
    user = User.load_current_user()
    if user:
        return dict(user=user)
    return dict()

@app.route('/')
def home():
    return redirect(url_for('login_view'))

@app.route('/login', methods = ['GET', 'POST'])
def login_view():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        user = User.get_by_username(form.email.data)
        if user is not None:
            # Authenticate and log in!
            if user.authenticate(form.password.data):
                flash(u'Logged in')
                return redirect(url_for('subscribe'))
        return 'Failure :('
    return render_template('login.html', form=form)    

@app.route('/flogin')
def flogin():
    return facebook.authorize(callback=url_for('facebook_authorized',
        next=request.args.get('next') or request.referrer or None,
        _external=True))

@app.route('/login/authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None:
        flash(u'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        ))
        return redirect(url_for('home'))
    session['oauth_token'] = (resp['access_token'], '')
    me = facebook.get('/me')
    user = User.get_by_username(me.data['email'])
    if user is not None:
        login(user)
    else:
        user = User(username=me.data['email'], name=me.data['name'])
        user.put()
        login(user)
    flash(u"You've logged in with Facebook")
    return redirect(url_for('subscribe'))

@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')

@app.route('/logout')
def logout_view():
    user_data = logout()
    if user_data is None:
        flash(u'No user to log out.')
        return redirect(url_for('home'))
    flash(u'Logged out')
    return redirect(url_for('home'))   

@app.route('/users/new')
def new_user():
    form = RegistrationForm()  
    return render_template('new_user.html', form=form)

@app.route('/users', methods = ['POST'])
def create_user():
    form = RegistrationForm(request.form)
    if form.validate():
        user = User(username = form.email.data)
        user.set_and_encrypt_password(form.password.data)
        user.put()
        login(user)
        flash(u'Thanks for registering')
        return redirect(url_for('subscribe'))   
    return redirect(url_for('new_user'))

@app.route('/account')
@login_required
def account():
    user = User.load_current_user()
    stripe.api_key = STRIPE_SECRET
    try:
        customer = stripe.Customer.retrieve(user.stripe_customer_id)
    except:
        customer = False
    mail = MailingAddress.get_by_username(user.username)
    return render_template('account.html', customer=customer, mail=mail)

@app.route('/address/edit')
@login_required
def edit_address():
    user = User.load_current_user()
    mail = MailingAddress.get_by_username(user.username)
    form = AddressForm(obj=mail)
    return render_template('address_edit.html', form=form)

@app.route('/address', methods=['POST'])
@login_required
def update_address():
    user = User.load_current_user()    
    form = AddressForm(request.form)
    m = MailingAddress.get_by_username(user.username)
    m.name = form.name.data
    m.address1 = form.address1.data
    m.address2 = form.address2.data
    m.zipcode = form.zipcode.data
    m.city = form.city.data
    m.state = form.state.data 
    m.country = form.country.data
    m.put()
    return redirect(url_for('account'))

@app.route('/cancel')
@login_required
def cancel_subscription():
    user = User.load_current_user()
    stripe.api_key = STRIPE_SECRET
    try:
        cu = stripe.Customer.retrieve(user.stripe_customer_id)
        cu.cancel_subscription()
        flash(u'Successfully Canceled')
    except:
        pass
    return redirect(url_for('account'))


@app.route('/subscribe', methods = ['GET', 'POST'])
@login_required
def subscribe():
    form = StripeSubscriptionForm(request.form)
    if request.method == 'POST':
        stripe.api_key = STRIPE_SECRET

        user = User.load_current_user()
        customer = stripe.Customer.create(
            card=form.stripeToken.data,
            plan="regular",
            email=user.username
        )
        user.stripe_customer_id = customer.id
        user.put()
        m = MailingAddress(username=user.username, name=form.name.data, address1 = form.address1.data,\
            address2=form.address2.data, zipcode=form.zipcode.data, city=form.city.data, state=form.state.data, country=form.country.data)
        m.put()
        context = dict()
        bodytext = render_template_string('emails/confirmation.txt', context=context)
        bodyhtml = render_template('emails/confirmation.html', context=context)
        mail.send_mail(sender="<welcome@sotmclub.com>", to=user.username,
                           subject="Welcome to the Club", body=bodytext, html=bodyhtml)
        return redirect(url_for('account'))
    return render_template('subscribe.html', form=form, pub_key=STRIPE_PUB_KEY)

@app.route('/admin_only')
@admin_required
def admin_only():
    """This view requires an admin account"""
    return 'Super-seekrit admin page.'

@app.route('/_ah/warmup')
def warmup():
    """App Engine warmup handler
    See http://code.google.com/appengine/docs/python/config/appconfig.html#Warming_Requests

    """
    return ''


## Error handlers
# Handle 404 errors
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Handle 500 errors
@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

