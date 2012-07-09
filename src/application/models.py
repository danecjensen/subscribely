"""
models.py

App Engine datastore models

"""


from google.appengine.ext import db

class MailingAddress(db.Model):
	"""Address to mail your subscription services product"""
	username = db.StringProperty()
	name = db.StringProperty()
	address1 = db.StringProperty()
	address2 = db.StringProperty()
	city = db.StringProperty()
	state = db.StringProperty()
	zipcode = db.StringProperty()
	country = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add=True)

	@classmethod
	def get_by_username(cls, username):
		q = db.Query(MailingAddress)
		q.filter('username = ', username)
		return q.get()