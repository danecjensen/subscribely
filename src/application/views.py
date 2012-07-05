"""
views.py

URL route handlers

Note that any handler params must match the URL route params.
For example the *say_hello* handler, handling the URL route '/hello/<username>',
  must be passed *username* as the argument.

"""

from application import app

from google.appengine.api import users
from google.appengine.runtime.apiproxy_errors import CapabilityDisabledError

from flask import render_template, request, flash, url_for, redirect

from models import ExampleModel
from decorators import admin_required
from forms import ExampleForm, RegistrationForm, LoginForm
from flaskext.auth import Auth, logout, login_required
from flaskext.auth.models.gae import User

import logging

Auth(app, login_url_name='login')

@app.route('/')
def home():
    return redirect(url_for('list_examples'))

@app.route('/login', methods = ['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.email.data
        user = User.get_by_username(username)
        if user is not None:
            # Authenticate and log in!
            if user.authenticate(form.password.data):
                return redirect(url_for('home'))
        return 'Failure :('
    return render_template('login.html', form=form)    


@app.route('/hello/<username>')
def say_hello(username):
    """Contrived example to demonstrate Flask's url routing capabilities"""
    return 'Hello %s' % username

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
        flash('Thanks for registering')
        return redirect(url_for('home'))   
    return redirect(url_for('new_user'))

@app.route('/examples', methods = ['GET', 'POST'])
@login_required
def list_examples():
    """List all examples"""
    examples = ExampleModel.all()
    form = ExampleForm()
    if form.validate_on_submit():
        example = ExampleModel(
            example_name = form.example_name.data,
            example_description = form.example_description.data,
            added_by = users.get_current_user()
        )
        try:
            example.put()
            example_id = example.key().id()
            flash(u'Example %s successfully saved.' % example_id, 'success')
            return redirect(url_for('list_examples'))
        except CapabilityDisabledError:
            flash(u'App Engine Datastore is currently in read-only mode.', 'info')
            return redirect(url_for('list_examples'))
    return render_template('list_examples.html', examples=examples, form=form)

 
@app.route('/examples/delete/<int:example_id>', methods = ['POST'])
@login_required
def delete_example(example_id):
    """Delete an example object"""
    example = ExampleModel.get_by_id(example_id)
    try:
        example.delete()
        flash(u'Example %s successfully deleted.' % example_id, 'success')
        return redirect(url_for('list_examples'))
    except CapabilityDisabledError:
        flash(u'App Engine Datastore is currently in read-only mode.', 'info')
        return redirect(url_for('list_examples'))

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

