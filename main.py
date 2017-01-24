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

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

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
	title = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	date_time_created = db.DateTimeProperty(auto_now_add = True)

class Blog(Handler):
	def get(self):
		posts = db.GqlQuery("select * from Posts order by date_time_created desc")
		self.render("frontpage.html", posts = posts)


class Post(Handler):
	def get(self):
		self.render("form.html")

	def post(self):
		title = self.request.get("title")
		content = self.request.get("content")
		params = dict(title = title, content = content)
		have_errors = False
		if not title:
			params["title_error"] = "Please add in a title"
			have_errors = True
		if not content:
			params["content_error"] = "Please add in content"
			have_errors = True
		if have_errors == False:
			blog_post = Posts(title = title, content = content)
			blog_post.put()
			self.write("Thanks!")
		else:
			self.render("form.html", **params)


app = webapp2.WSGIApplication([('/blog', Blog), ('/newpost', Post)], debug=True)
