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
import time

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

# Creates a random string of letters for salt encryption


def make_salt(length=5):
    salt_list = [random.choice(
        string.ascii_lowercase + string.ascii_uppercase + string.digits)
        for x in range(length)]
    return ''.join(salt_list)

# Creates a hash of the password, by including the username, password and salt


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return "%s,%s" % (salt, h)

# Checks if the password is valid


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# Checks if the username is valid


def valid_username(username):
    return username and re.compile(r"^[a-zA-Z0-9_-]{3,20}$").match(username)

# Checks if the password is valid


def valid_password(password):
    return password and re.compile(r"^.{3,20}$").match(password)

# Checks if the email is valid


def valid_email(email):
    return not email or re.compile(r"^[\S]+@[\S]+.[\S]+$").match(email)

# Secret string to use for HMAC
# Ideally should be stored in a separate module

SECRET = "asoidjo1ij4o5i10-3031928309aposk;lcsoafaosijd"

# Creates a hash of the current password


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

# Creates a value in the unhashed | hashed format


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

# Checks if the hash is valid


def check_secure_val(h):
    val = h.split("|")[0]
    if h == make_secure_val(val):
        return val

# Handler boilerplate


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# Validate(self) checks if the user is currently logged in

    def validate(self):
        tmp = self.request.cookies.get('user_id')
        self.uid = tmp and check_secure_val(tmp)
        logged_in_user = self.uid and Users.by_id(int(self.uid))
        return logged_in_user

# Users database


class Users(db.Model):
    name = db.StringProperty(required=True)
    password_hashed = db.StringProperty(required=True)
    email = db.StringProperty()


# Retrieve instance by name

    @classmethod
    def by_name(cls, name):
        u = Users.all().filter('name = ', name).get()
        return u

# Retrieve instance by id

    @classmethod
    def by_id(cls, uid):
        return Users.get_by_id(uid)

# Posts database


class Posts(db.Model):
    name = db.StringProperty(required=True)
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    likes = db.ListProperty(str)
    date_time_created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_name(cls, name):
        u = Posts.all().filter('name = ', name).get()
        return u

    @classmethod
    def by_id(cls, uid):
        return Posts.get_by_id(uid)

# Comments database


class Comments(db.Model):
    post_author = db.StringProperty(required=True)
    name = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    date_time_created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_name(cls, name):
        u = Comments.all().filter('name = ', name).get()
        return u

    @classmethod
    def by_id(cls, uid):
        return Comments.get_by_id(uid)


class Blog(Handler):

    def get(self):
        self.user = self.validate()
        posts = db.GqlQuery(
            "select * from Posts order by date_time_created desc")
        if self.user:
            self.render("frontpage.html", posts=posts, name=self.user.name)
        else:
            self.render("frontpage.html", posts=posts)


class PostedPage(Handler):

    def get(self, post_id):
        cursor_db = db.GqlQuery(
            """select * from Comments where post_id = %i
            order by date_time_created desc"""
            % int(post_id))
        post = Posts.get_by_id(int(post_id))
        self.user = self.validate()
        if post:
            if self.user:
                self.render("blogpost.html", post=post,
                            name=self.user.name, comments=cursor_db)
            else:
                self.render("blogpost.html", post=post, comments=cursor_db)
        else:
            error = "This post doesn't exist"
            self.render('notification.html', error=error)


class Post(Handler):

    def get(self):
        self.user = self.validate()
        if self.user:
            self.render("form.html", name=self.user.name)
        else:
            self.redirect('/login')

    def post(self):
        self.user = self.validate()
        self.likes = []
        self.title = self.request.get("title")
        self.content = self.request.get("content")
        params = dict(name=self.user.name, title=self.title,
                      content=self.content)
        have_errors = False
        if self.user:
            if not self.title:
                params["title_error"] = "Please add in a title"
                have_errors = True
            if not self.content:
                params["content_error"] = "Please add in content"
                have_errors = True
            if not have_errors:
                blog_post = Posts(name=self.user.name, title=self.title,
                                  content=self.content)
                blog_post.put()
                self.redirect("/blog/%s" % str(blog_post.key().id()))
            else:
                self.render("form.html", **params)
        else:
            self.redirect('/login')


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
        params = dict(username=self.username, email=self.email)
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

        if not have_errors:
            user = Users(name=self.username,
                         password_hashed=make_pw_hash(
                             self.username, self.password),
                         email=self.email)
            user.put()
            self.response.headers.add_header(
                'Set-Cookie', '%s = %s; Path = /'
                % ('user_id', make_secure_val(str(user.key().id()))))
            self.redirect("/welcome")
        else:
            self.render("signup.html", **params)


class Welcome(Handler):

    def get(self):
        self.user = self.validate()
        if self.user:
            self.render("welcome.html", username=self.user.name)
        else:
            self.redirect('/signup')


class Login(Handler):

    def get(self):
        self.user = self.validate()
        if self.user:
            self.redirect('/blog')
        else:
            self.render('login.html')

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        params = dict()
        if (Users.by_name(self.username)) and valid_pw(
                self.username, self.password,
                Users.by_name(self.username).password_hashed):
                    self.response.headers.add_header(
                        'Set-Cookie', '%s=%s; Path=/' % (
                           'user_id', make_secure_val(
                                str(Users.by_name(self.username).key().id()))))
                    self.redirect('/welcome')
        else:
            error = "Invalid Login"
            self.render("login.html", error=error)


class Logout(Handler):

    def get(self):
        self.user = self.validate()
        if self.user:
            self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
            self.redirect('/login')
        else:
            self.redirect('/signup')


class Edit(Handler):

    def get(self, post_id):
        self.user = self.validate()
        self.uname = Posts.by_id(int(post_id))
        if self.user:
            if self.user.name == self.uname.name:
                self.render('edit.html', name=self.user.name)
            else:
                self.redirect('/blog')
        else:
            self.render('login.html')

    def post(self, post_id):
        self.user = self.validate()
        self.title = self.request.get("title")
        self.content = self.request.get("content")
        self.uname = Posts.by_id(int(post_id))
        if self.user:
            if self.user.name == self.uname.name:
                params = dict(name=self.user.name,
                              title=self.title, content=self.content)
                have_errors = False
                if not self.title:
                    params["title_error"] = "Please add in a title"
                    have_errors = True
                if not self.content:
                    params["content_error"] = "Please add in content"
                    have_errors = True
                if not have_errors:
                    blog_post = Posts.by_id(int(post_id))
                    blog_post.title = self.title
                    blog_post.content = self.content
                    blog_post.put()
                    self.redirect("/blog/%s" % str(blog_post.key().id()))
                else:
                    self.render("edit.html", **params)
        else:
            self.redirect('/login')


class Delete(Handler):

    def get(self, post_id):
        self.user = self.validate()
        self.uname = Posts.by_id(int(post_id))
        if self.user:
            if self.user.name == self.uname.name:
                Posts.delete(self.uname)
                error = "You have deleted the post"
                self.render('notification.html', error=error)
            else:
                error = "You can only delete your own posts"
                self.render('notification.html', error=error)
        else:
            self.redirect('/login')


class Comment(Handler):

    def get(self, post_id):
        self.user = self.validate()
        if self.user:
            self.render("comment.html", name=self.user.name)
        else:
            self.redirect('/login')

    def post(self, post_id):
        self.user = self.validate()
        self.content = self.request.get("content")
        self.post = Posts.by_id(int(post_id))
        params = dict(name=self.user.name, content=self.content)
        have_errors = False
        if self.user:
            if self.post:
                if not self.content:
                    params["content_error"] = "Please add in content"
                    have_errors = True
                if not have_errors:
                    blog_post_comment = (Comments(
                        post_author=Posts.by_id(int(post_id)).name,
                        post_id=int(post_id), name=self.user.name,
                        content=self.content))
                    blog_post_comment.put()
                    error = "You have posted your comment"
                    self.render("notification.html", error=error)
                else:
                    self.render("comment.html", **params)
            else:
                error = "This post doesn't exist"
                self.render("notification.html", error=error)
        else:
            self.redirect('/login')


class DeleteComments(Handler):

    def get(self, comment_id):
        self.user = self.validate()
        self.commentsPost = Comments.by_id(int(comment_id))
        if self.user:
            if self.commentsPost:
                if self.user.name == self.commentsPost.name:
                    Comments.delete(self.commentsPost)
                    error = "You have deleted the comment"
                    self.render('notification.html', error=error)
                else:
                    error = "You can only delete your own comments"
                    self.render('notification.html', error=error)
            else:
                error = "This comment doesn't exist"
                self.render("notification.html", error=error)
        else:
            self.redirect('/login')


class EditComments(Handler):

    def get(self, comment_id):
        self.user = self.validate()
        self.commentsPost = Comments.by_id(int(comment_id))
        if self.user:
            if self.commentsPost:
                if self.user.name == self.commentsPost.name:
                    self.render('editcomments.html', name=self.user.name)
                else:
                    error = "You can only edit your own comment"
                    self.render('notification.html', error=error)
            else:
                error = "This comment doesn't exist"
                self.render("notification.html", error=error)
        else:
            self.redirect('/login')

    def post(self, comment_id):
        self.user = self.validate()
        self.content = self.request.get("content")
        params = dict(name=self.user.name, content=self.content)
        self.commentsPost = Comments.by_id(int(comment_id))
        have_errors = False
        if self.user:
            if self.commentsPost:
                if not self.content:
                    params["content_error"] = "Please add in content"
                    have_errors = True
                if not have_errors:
                    blog_post_comment = Comments.by_id(int(comment_id))
                    blog_post_comment.content = self.content
                    blog_post_comment.put()
                    self.redirect("/blog")
                else:
                    self.render("editcomments.html", **params)
            else:
                error = "This comment doesn't exist"
        else:
            self.redirect('/login')


class LikePosts(Handler):

    def get(self, post_id):
        self.user = self.validate()
        self.postName = Posts.by_id(int(post_id))
        self.likedList = self.postName.likes
        if self.user:
            if self.postName:
                if ((self.user.name != self.postName.name) and
                        (self.user.name not in self.likedList)):
                    self.postName.likes.append(self.user.name)
                    self.postName.put()
                    error = "Thanks for liking!"
                    self.render("notification.html", error=error)
                elif self.user.name in self.likedList:
                    error = "You can only like posts once"
                    self.render("notification.html", error=error)
                elif self.user.name == self.postName.name:
                    error = "You can't like your own posts"
                    self.render("notification.html", error=error)
                else:
                    self.redirect('/login')
            else:
                error = "This post doesn't exist"
                self.render("notification.html", error=error)
        else:
            self.redirect('/login')

app = webapp2.WSGIApplication([('/blog', Blog),
                               ('.*/newpost', Post),
                               ('/blog/([0-9]+)', PostedPage),
                               ('/signup', Signup),
                               ('/welcome', Welcome),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/edit/([0-9]+)', Edit),
                               ('/blog/delete/([0-9]+)', Delete),
                               ('/blog/comment/([0-9]+)', Comment),
                               ('/blog/deletecomments/([0-9]+)',
                                DeleteComments),
                               ('/blog/editcomments/([0-9]+)', EditComments),
                               ('/blog/like/([0-9]+)', LikePosts)],
                              debug=True)
