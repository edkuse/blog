import hashlib
import hmac
import json
import os
import random
import re
import string
import time
import jinja2
import webapp2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

SECRET = "the rain in spain falls mainly on the plain"

class BlogHandler(webapp2.RequestHandler):
	# override the webapp2.RequestHandler.__init__() method
	def __init__(self, request, response):
		self.initialize(request, response)

		#
		# custom initialization 
		#

		# check if user_id cookie exists and is valid
		uid = self.get_secure_cookie('user_id')
		self.user = uid and User.get_by_id(int(uid))

		# if self.user is None (not logged in) and trying to edit/create something, redirect to login page
		if not self.user and self.request.route.name in ['add-entry', 'edit-entry', 'delete-item', 'edit-comment']:
			self.redirect('/login')

	def write(self, template, **params):
		t = jinja_env.get_template(template)

		# always send self.user to template
		params.update({'user': self.user})

		self.response.write(t.render(params))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'{0}={1}; Path=/'.format(name, cookie_val))

	def get_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		# delete cookie for user
		self.response.delete_cookie('user_id')


class MainHandler(BlogHandler):
	def get(self):
		username = self.request.get('username')
		uid = None

		if username:
			u = User.get_by_name(username)

			uid = u and u.key().id()

		if not uid and self.user and self.user.name:
			username = self.user.name
			uid = self.user.key().id()

		entries = uid and Entry.get_by_user(uid)

		# favorites
		favorites = self.user and Favorite.get_by_user(self.user.key().id())
		f = []

		if favorites:
			for ff in favorites:
				f.append(ff.entry)

		# comments
		comments = {}
		if entries:
			for e in entries:
				comments[e.key().id()] = Comment.get_by_entry(e.key().id()).count()

		self.write(
			'entries.html',
			username=username,
			users=User.get_all(),
			entries=entries,
			favorites=f,
			comments=comments
		)


class GetEntryHandler(BlogHandler):
	def get(self, eid, error_content=None):
		entry = Entry.get_by_id(int(eid))
		u = entry and User.get_by_id(entry.user)

		# favorites
		favorites = self.user and Favorite.get_by_user(self.user.key().id())
		f = []

		# comments
		comments = Comment.get_by_entry(int(eid))

		if favorites:
			for ff in favorites:
				f.append(ff.entry)

		self.write(
			'entry.html',
			entry=entry,
			username=u and u.name,
			favorites=f,
			comments=comments,
			error_content=error_content
		)

	def post(self, eid):
		# Comment has been added/updated
		cid = self.request.get('cid')
		content = self.request.get('content')

		if cid is not None:
			has_errors = False
			error_content = ''

			# validate content
			if not content.strip():
				error_content = "Comment text is required."
				has_errors = True

			if has_errors:
				self.get(eid, error_content)

			else:
				# are we adding or updating a comment?
				if cid and cid.isdigit():
					cid = int(cid)

					# new
					if cid == 0:
						c = Comment.add(
							self.user,
							#int(self.user.key().id()),
							int(eid),
							content
						)

						cid = c.key().id()

					# update
					else:
						c = Comment.update(
							int(cid),
							int(self.user.key().id()),
							int(eid),
							content
						)

				# When doing a redirect, comments do not update... Found following solution on stack overflow
				# http://stackoverflow.com/questions/16879275/why-webapp2-redirect-to-a-page-but-its-not-reload
				time.sleep(1)
				self.redirect('/entry/{0}'.format(eid))


class LoginHandler(BlogHandler):
	def write_error(self):
		self.write(
			'login.html',
			error_login="Invalid Login"
		)

	def get(self):
		self.write('login.html')

	def post(self):
		# validate credentials
		username = self.request.get('username')
		password = self.request.get('password')

		if username and password:
			rs = User.get_by_name(username)

			if rs and is_valid_pw(username, password, rs.password):
				self.set_secure_cookie('user_id', str(rs.key().id()))
				self.redirect('/')
			else:
				self.write_error()
		else:
			self.write_error()


class LogoutHandler(BlogHandler):
	def get(self):
		self.logout()
		self.redirect('/')


class SignupHandler(BlogHandler):
	def get(self):
		self.write('signup.html')

	def post(self):
		has_errors = False
		error_username = ''
		error_password = ''
		error_verify = ''
		error_email = ''

		# validate username
		username = self.request.get('username')
		if not valid_username(username):
			error_username = "That's not a valid username."
			has_errors = True

		# validate password
		password = self.request.get('password')
		if not valid_password(password):
			error_password = "That wasn't a valid password."
			has_errors = True

		# validate passwords match
		verify = self.request.get('verify')
		if password != verify:
			error_verify = "Your passwords didn't match."
			has_errors = True

		# validate email
		email = self.request.get('email')
		if email.strip() and not valid_email(email):
			error_email = "That's not a valid email.'"
			has_errors = True

		# if no validation errors yet, check if username already exists
		if not has_errors:
			u = User.get_by_name(username)
			if u:
				error_username = "That username already exists!"
				has_errors = True

		if has_errors:
			self.write(
				'signup.html',
				username=username,
				error_username=error_username,
				error_password=error_password,
				error_verify=error_verify,
				email=email,
				error_email=error_email
			)
		else:
			# load/save to db
			u = User.add(
				username,
				password,
				email
			)

			self.login(u)
			self.redirect('/')


class EditEntryHandler(BlogHandler):
	def get(self, eid=None):
		params = {'eid': eid}

		if eid and eid.isdigit():
			e = Entry.get_by_id(int(eid))
			if not e:
				params['eid'] = None
			else:
				params.update({'subject': e.subject, 'content': e.content})

		self.write("edit.html", **params)

	def post(self, eid=None):
		has_errors = False
		error_subject = ''
		error_content = ''

		# validate subject
		subject = self.request.get('subject')
		if not subject.strip():
			error_subject = "Subject is required."
			has_errors = True

		# validate content
		content = self.request.get('content')
		if not content.strip():
			error_content = "Content is required."
			has_errors = True

		if has_errors:
			self.write(
				'edit.html',
				subject=subject,
				content=content,
				error_subject=error_subject,
				error_content=error_content
			)
		else:
			# are we adding or updating?
			if eid and eid.isdigit():
				e = Entry.update(
					int(eid),
					int(self.user.key().id()),
					subject,
					content
				)

			else:
				# add to datastore
				e = Entry.add(
					int(self.user.key().id()),
					subject,
					content
				)

				eid = e.key().id()

			self.redirect('/entry/{0}'.format(eid))


class DeleteHandler(BlogHandler):
	def post(self):
		item = self.request.get('item')
		typ = self.request.get('type')
		uid = self.user and self.user.key().id()

		# are we deleting entry or comment?
		if typ == 'entry':
			result = item.isdigit() and Entry.remove(int(item), uid)
		elif typ == 'comment':
			result = item.isdigit() and Comment.remove(int(item), uid)

		# http://stackoverflow.com/questions/16879275/why-webapp2-redirect-to-a-page-but-its-not-reload
		time.sleep(1)

		self.response.headers['Content-Type'] = 'application/json'
		self.response.write(json.dumps({
			'result': True if result else False
		}))


class FavoriteHandler(BlogHandler):
	def post(self):
		eid = self.request.get('entry')
		action = self.request.get('action')
		uid = self.user and self.user.key().id()
		result = False

		if uid and eid and eid.isdigit():
			eid = int(eid)
			f = Favorite.get_by_entry(uid, eid)

			if action == 'add':
				# user can't like same entry again
				if not f:
					f = Favorite.add(user=uid, entry=eid)
					result = True if f else False

			else:
				f = Favorite.remove(user=uid, entry=eid)
				result = True

		self.response.headers['Content-Type'] = 'application/json'
		self.response.write(json.dumps({
			'result': result
		}))


class EditCommentHandler(BlogHandler):
	def post(self):
		cid = self.request.get('comment')
		content = self.request.get('content')
		uid = self.user and self.user.key().id()
		result = False

		if uid and cid and cid.isdigit():
			c = Comment.update(
				int(cid),
				uid,
				content
			)

			result = True if c else False

		# http://stackoverflow.com/questions/16879275/why-webapp2-redirect-to-a-page-but-its-not-reload
		time.sleep(1)

		self.response.headers['Content-Type'] = 'application/json'
		self.response.write(json.dumps({
			'result': result
		}))


#
# Database Entities
#
class User(db.Model):
	name = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def get_all(cls, sortby='name'):
		return User.all().order(sortby)

	@classmethod
	def get_by_name(cls, name):
		return User.all().filter('name =', name).get()

	@classmethod
	def add(cls, name, pw, email=None):
		u = User(name = name, password = make_pw_hash(name, pw), email = email)
		u.put()

		return u


class Entry(db.Model):
	user = db.IntegerProperty(required = True)
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	@classmethod
	def get_by_user(cls, uid):
		return Entry.all().filter('user =', uid).order('-created')

	@classmethod
	def add(cls, user, subject, content):
		e = Entry(user=user, subject=subject, content=content)
		e.put()

		return e

	@classmethod
	def update(cls, eid, user, subject, content):
		e = Entry.get_by_id(eid)

		# ensure that user who created entry is same as who is updating
		if user == e.user:
			e.subject = subject
			e.content = content
			e.put()

			return e

	@classmethod
	def remove(cls, eid, uid):
		e = Entry.get_by_id(eid)

		# make sure that logged in user is deleting their entry
		if e and e.user == uid:
			e.delete()
			return True


class Favorite(db.Model):
	user = db.IntegerProperty(required = True)
	entry = db.IntegerProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

	@classmethod
	def get_by_user(cls, uid):
		return Favorite.all().filter('user =', uid).order('-entry')

	@classmethod
	def get_by_entry(cls, uid, eid):
		return Favorite.all().filter('user =', uid).filter('entry =', eid).order('-entry').get()

	@classmethod
	def add(cls, user, entry):
		f = Favorite(user=user, entry=entry)
		f.put()

		return f

	@classmethod
	def remove(cls, user, entry):
		f = cls.get_by_entry(uid=user, eid=entry)

		# make sure that logged in user is unliking their liked entry
		if f and f.user == user:
			f.delete()
			return True


class Comment(db.Model):
	user = db.ReferenceProperty(required = True)
	entry = db.IntegerProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	@classmethod
	def get_by_user(cls, uid):
		return Comment.all().filter('user =', uid).order('-entry')

	@classmethod
	def get_by_entry(cls, eid):
		return Comment.all().filter('entry =', eid).order('created')

	@classmethod
	def add(cls, user, entry, content):
		c = Comment(user=user, entry=entry, content=content)
		c.put()

		return c

	@classmethod
	def update(cls, cid, user, content):
		c = Comment.get_by_id(cid)

		# ensure that user who created comment is same as who is editing
		if user == c.user.key().id():
			c.content = content
			c.put()

			return c

	@classmethod
	def remove(cls, cid, user):
		c = Comment.get_by_id(cid)

		# make sure that logged in user is same as comment owner
		if c and c.user.key().id() == user:
			c.delete()
			return True


#
# cookie hash functions
#
def make_secure_val(val):
	return '{0}|{1}'.format(val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

#
# user password hash functions
#
def make_salt():
	return ''.join(random.choice(string.letters) for i in range(5))

def make_pw_hash(name, pw, salt=None):
	salt = salt or make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()

	return '{0},{1}'.format(salt, h)

def is_valid_pw(name, pw, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, pw, salt)

#
# signup form validation functions
#
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return PASSWORD_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
	return EMAIL_RE.match(email)


app = webapp2.WSGIApplication([
	webapp2.Route('/', handler=MainHandler, name='home'),
	webapp2.Route('/login', handler=LoginHandler, name='login'),
	webapp2.Route('/logout', handler=LogoutHandler, name='logout'),
	webapp2.Route('/signup', handler=SignupHandler, name='signup'),
	webapp2.Route('/edit', handler=EditEntryHandler, name='add-entry'),
	webapp2.Route('/edit/<eid:\d+>', handler=EditEntryHandler, name='edit-entry'),
	webapp2.Route('/entry/<eid:\d+>', handler=GetEntryHandler, name='get-entry'),
	webapp2.Route('/delete', handler=DeleteHandler, name='delete-item'),
	webapp2.Route('/favorite', handler=FavoriteHandler, name='favorite'),
	webapp2.Route('/comment/edit', handler=EditCommentHandler, name='edit-comment')
], debug=True)
