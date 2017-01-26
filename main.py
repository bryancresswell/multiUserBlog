# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import webapp2
import jinja2
import os
import re
import hmac
import string
import random
import hashlib

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

def make_salt(length = 5):
	salt_list = [random.choice(
				 string.ascii_lowercase + string.ascii_uppercase + string.digits) 
				 for x in range(length)]
	return ''.join(salt_list)

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return "%s,%s" % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def valid_username(username):
	return username and re.compile(r"^[a-zA-Z0-9_-]{3,20}$").match(username)

def valid_password(password):
	return password and re.compile(r"^.{3,20}$").match(password)

def valid_email(email):
	return not email or re.compile(r"^[\S]+@[\S]+.[\S]+$").match(email)

SECRET = "asoidjo1ij4o5i10-3031928309aposk;lcsoafaosijd"

def hash_str(s):
	return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
	return "%s|%s" %(s, hash_str(s))

def check_secure_val(h):
	val = h.split("|")[0]
	if h == make_secure_val(val):
		return val

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))


class Posts(db.Model):
	name = db.StringProperty(required = True)
	title = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	date_time_created = db.DateTimeProperty(auto_now_add = True)

	@classmethod
	def by_name(cls, name):
		u = Posts.all().filter('name = ', name).get()
		return u

	@classmethod
	def by_id(cls, uid):
		return Posts.get_by_id(uid)

class Blog(Handler):
	def get(self):
		tmp = self.request.cookies.get('user_id')
		self.uid = tmp and check_secure_val(tmp)
		self.user = self.uid and Users.by_id(int(self.uid))
		posts = db.GqlQuery("select * from Posts order by date_time_created desc")
		if self.user:
			self.render("frontpage.html", posts = posts, name = self.user.name)
		else:
			self.redirect('/login')

class PostedPage(Handler):
	def get(self, post_id):
		post = Posts.get_by_id(int(post_id))
		tmp = self.request.cookies.get('user_id')
		self.uid = tmp and check_secure_val(tmp)
		self.user = self.uid and Users.by_id(int(self.uid))
		self.name = self.user.name
		if not post:
			self.error(404)
		else:
			self.render("blogpost.html", post = post, name = self.name)


class Post(Handler):
	def get(self):
		tmp = self.request.cookies.get('user_id')
		self.uid = tmp and check_secure_val(tmp)
		self.user = self.uid and Users.by_id(int(self.uid))
		if self.user:
			self.render("form.html", name = self.user.name)
		else:
			self.redirect('/login')

	def post(self):
		tmp = self.request.cookies.get('user_id')
		self.uid = tmp and check_secure_val(tmp)
		self.user = self.uid and Users.by_id(int(self.uid))
		self.title = self.request.get("title")
		self.content = self.request.get("content")
		params = dict(name = self.user.name, title = self.title, content = self.content)
		have_errors = False
		if not self.title:
			params["title_error"] = "Please add in a title"
			have_errors = True
		if not self.content:
			params["content_error"] = "Please add in content"
			have_errors = True
		if have_errors == False:
			blog_post = Posts(name = self.user.name, title = self.title, content = self.content)
			blog_post.put()
			self.redirect("/blog/%s" % str(blog_post.key().id()))
		else:
			self.render("form.html", **params)

class Signup(Handler):
	def get(self):
		self.render("signup.html")

	def post(self):
		self.username = self.request.get("username")
		self.password = self.request.get("password")
		self.verify = self.request.get("verify")
		self.email = self.request.get("email")
		have_errors = False
		u = Users.by_name(self.username)
		params = dict(username = self.username, email = self.email)
		if not valid_username(self.username):
			params["usernameError"] = "Please enter a valid username"
			have_errors = True

		elif u:
			params["usernameError"] = "That username is in use"
			have_errors = True

		if not valid_password(self.password):
			params["passwordError"] = "Please enter a valid password"
			have_errors = True

		elif self.password != self.verify:
			params["verifyError"] = "Please ensure that your passwords match"
			have_errors = True

		if not valid_email(self.email):
			params["emailError"] = "Please enter a valid e-mail address"
			have_errors = True

		if have_errors == False:
			user = Users(name = self.username, 
						 password_hashed = make_pw_hash(self.username, self.password), 
						 email = self.email)
			user.put()
			self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/'
											 % ('user_id', make_secure_val(str(user.key().id()))))
			self.redirect("/welcome")
		else:
			self.render("signup.html", **params)

class Users(db.Model):
	name = db.StringProperty(required = True)
	password_hashed = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_name(cls, name):
		u = Users.all().filter('name = ', name).get()
		return u

	@classmethod
	def by_id(cls, uid):
		return Users.get_by_id(uid)

class Welcome(Handler):
	def get(self):
		tmp = self.request.cookies.get('user_id')
		self.uid = tmp and check_secure_val(tmp) 
		self.user = self.uid and Users.by_id(int(self.uid))
		if self.user:
			self.render("welcome.html", username = self.user.name)
		else:
			self.redirect('/signup')

class Login(Handler):
	def get(self):
		tmp = self.request.cookies.get('user_id')
		self.uid = tmp and check_secure_val(tmp) 
		self.user = self.uid and Users.by_id(int(self.uid))
		if self.user:
			self.redirect('/blog')
		else:
			self.render('login.html')

	def post(self):
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		params = dict()
		if Users.by_name(self.username) and valid_pw(self.username, 
													 self.password, 
													 Users.by_name(self.username).password_hashed):
			self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/'
											 % ('user_id', 
											 	make_secure_val(str(Users.by_name(self.username).key().id()))))
			self.redirect('/welcome')
		else:
			error = "Invalid Login"
			self.render("login.html", error = error)

class Logout(Handler):
	def get(self):
		tmp = self.request.cookies.get('user_id')
		self.uid = tmp and check_secure_val(tmp) 
		self.user = self.uid and Users.by_id(int(self.uid))
		if self.user:
			self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
			self.redirect('/login')
		else:
			self.redirect('/signup')


app = webapp2.WSGIApplication([('/blog', Blog), 
							   ('.*/newpost', Post), 
							   ('/blog/([0-9]+)', PostedPage),
							   ('/signup', Signup),
							   ('/welcome', Welcome),
							   ('/login', Login),
							   ('/logout', Logout)], 
							   debug=True)
