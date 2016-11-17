#!/usr/bin/env python
# TO DO:
# 1. Add ability to browse posts, browsePosts
# 2. Add ability to search posts by title and keywords
#       - create Keywords table
# 3. Add column with list of keyword tags - query all unique tags

import os
import jinja2
import webapp2
import hashlib
import hmac
import random
import string
from google.appengine.api import memcache
from google.appengine.ext import db
import datetime
import time
import bleach

# contains secret string
import sources
# validation by regex
from validators import valid_username, valid_password, valid_email, check_duplicate_user
# database models
from models import User, Post, Comment, Like

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

# secret string
secret = sources.secret()

# Custom jinja2 filter for returning first line of content
def firstline(content):
    return content.split('\n')[0]

# Custom jinja2 filter for returning standard month day year format
def standard_date(date):
    return date.strftime('%b %d, %Y')

def markdown(content):
    bleached_content = bleach.clean(content,
        tags = ['strong','b','i','em','h1','h2','pre','code', 'br', 'u', 'li', 'ul', 'ol'])
    c = bleached_content.split('\n')
    # first line (description) will be a bigger font size
    c[0] = '<h3>%s</h3>' % c[0]
    content = '\n'.join(c)
    content = content.replace('\n', '<br>')
    return content

def find_username(user_id):
    # finds username for a post
    key = db.Key.from_path('User', int(user_id))
    user = db.get(key)
    return user.username

jinja_env.filters['firstline'] = firstline
jinja_env.filters['standard_date'] = standard_date
jinja_env.filters['markdown'] = markdown
jinja_env.filters['find_username'] = find_username

def imageCheck(url):
    if url[:19] == 'http://i.imgur.com/':
        return url

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # everything cookie related
    # -------------------------
    def make_secure_val(self, val):
        return "%s|%s" % (val, hmac.new(secret, val).hexdigest())

    def check_secure_val(self, secure_val):
        # secure_val is checked by splitting to two
        val = secure_val.split('|')[0]
        key = secure_val.split('|')[1]
        # create a hashed value of val
        hashed = self.make_secure_val(val).split('|')[1]
        # both key and hashed has to always remain equal to confirm that there is no tampering
        if key == hashed:
            return val

    def set_secure_cookie(self, name, val):
        cookie_val = self.make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def set_remember_cookie(self, name, val):
        cookie_val = self.make_secure_val(val)
        # expiry time is set one year from login
        expires = datetime.datetime.utcnow() + datetime.timedelta(days=365)
        self.response.set_cookie(name, cookie_val, expires=expires, path='/')

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and self.check_secure_val(cookie_val)

    def current_user(self):
        uid_cookie = self.read_secure_cookie('user_id')
        if uid_cookie:
          uid = uid_cookie.split('|')[0]
          key = db.Key.from_path('User', int(uid))
          return db.get(key)

    def logout(self, name):
        self.response.headers.add_header('Set-Cookie', '%s=; Path=/' % name)

    # makes encrypted sha256 passwords
    # --------------------------------
    def make_hash(self, name, password, salt):
        return hashlib.sha256(name + password + salt).hexdigest()

    def make_salt(self):
        # salt set to 5 characters
        return "".join(random.choice(string.letters) for x in xrange(5))

# key generator functions
# -----------------------
def user_key(user_id):
    return db.Key.from_path('User', user_id)

def post_key(post_id, user_key):
    return db.Key.from_path('Post', post_id, parent = user_key)

def comment_key(comment_id, post_id, user_key):
    return db.Key.from_path('Comment', comment_id, parent = post_key(post_id, user_key))

class SignUp(Handler):
    def get(self):
        message = self.request.get('message')
        username = self.request.get('username')
        email = self.request.get('email')
        user_logged = ''
        u = self.current_user()
        if u:
            user_logged = u.username
        self.render('signup.html',
            message = message,
            username = username,
            email = email,
            user_logged = user_logged)

    def post(self):
        username = self.request.get('username') or None
        email = self.request.get('email') or None
        password = self.request.get('password')
        verify = self.request.get('verify')
        security_q = self.request.get('security_q')
        security_a = self.request.get('security_a')
        msg = []
        err = False

        if not valid_username(username):
            msg.append('Invalid Username')
            err = True

        if check_duplicate_user(username, User):
            msg.append('Duplicate Username, Choose another one')
            err = True

        if not valid_password(password):
            msg.append('Invalid Password')
            err = True

        if not valid_email(email):
            msg.append('Invalid Email')
            err = True

        if not security_a:
            msg.append('Security Question and Answer required')
            err = True

        if password != verify:
            msg.append('Passwords do not match')
            err = True

        if len(password) < 8:
            msg.append('Password must be 8 or more characters')
            err = True

        if err:
            # create whole message from all error messages
            message = ", ".join(msg)
            self.render('/signup.html',
                message = message,
                username = username,
                email = email)
        else:
            # passed all requirements
            # create hashed password for each user
            salt = self.make_salt()
            hashed_pwd = self.make_hash(username, password, salt)
            security_a_hashed = self.make_hash(security_q, security_a, salt)

            # save to database
            u = User(username = username,
                email = email,
                password = hashed_pwd,
                security_q = security_q,
                security_a = security_a_hashed,
                salt = salt)
            u.put()
            self.redirect('/login?username=%s&status=signedup' % username)

class Login(Handler):
    def get(self):
        username = self.request.get('username') or ''
        status = self.request.get('status') or None

        self.logout('user_id')
        self.render('login.html', username = username, status = status)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        remember = self.request.get('remember')
        err = ''

        if (username and password):
            user = User.all().filter('username =', username).get()
            if user:
                uid = user.key().id()
                hashed_pwd = user.password
                salt = user.salt
                

                # make a hash of what the user entered
                hashed = self.make_hash(username, password, salt)

                # check if passwords match
                if hashed == hashed_pwd:
                    # successful login
                    if remember:
                        self.set_remember_cookie('user_id', str(uid))
                    else:
                        self.set_secure_cookie('user_id', str(uid))
                    self.redirect('/')
                else:
                    # passwords dont match
                    err = 'wrong_pwd'
            else:
                # username does not exist
                err = 'wrong_user'
        else:
            err = 'blank'

        if err:
            self.render('login.html', status = err)

class Forgot(Handler):
    def get(self):
        self.render('forgot.html')

    def post(self):
        username = self.request.get('username')
        security_q = self.request.get('security_q')
        security_a = self.request.get('security_a')
        err_msg = []
        message = ''
        err = False
        salt = ''

        if not username:
            err_msg.append('Please enter Username')
            err = True

        if not security_a:
            err_msg.append('Please enter Security Answer')
            err = True

        if not valid_username(username):
            err_msg.append('Invalid Username')
            err = True

        if not err:

            user = User.all().filter('username =', username).get()
            if user:
                uid = user.key().id()
                q_db = user.security_q
                a_db = user.security_a
                salt = user.salt
            else:
                err_msg.append("Did not find Username")
                err = True

            if salt:
                if (q_db == security_q) and (a_db == self.make_hash(security_q, security_a, salt)):
                    err = False
                else:
                    err_msg.append("Security fields do not match")
                    err = True

        if err:
            message = ", ".join(err_msg)
            self.render('forgot.html', message = message)
        else:
            # success : set cookie to user
            self.set_secure_cookie('user_id', str(uid))
            self.redirect('/change_pwd')

class ChangePwd(Handler):
    def get(self):
        # check cookie
        u = self.current_user()
        if u:
            self.render('changepwd.html', username = u.username)
        else:
            self.render('404error.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        err = False

        if not valid_password(password):
            err_msg = 'Invalid Password'
            err = True

        if password != verify and err == False:
            err_msg = 'Password and Verify Password do not match'
            err = True

        if len(password) < 8:
            err_msg = 'Password must be 8 characters'
            err = True

        if err:
            self.render('changepwd.html', message = err_msg)
        else:
            # update db
            u = self.current_user()
            if u:
                u.password = self.make_hash(username, password, u.salt)
                u.put()
            self.redirect('/blogs')

# browse all users' posts based on a username link
class ViewUser(Handler):
    def get(self):
        '''
        If the user is logged in and matches the view_user_id, a PRIVATE facing page with EDIT / DELETE buttons will be rendered
        If the user is logged in and does not match the view_user_id, a PUBLIC facing page will be rendered
        if the user is not logged then it will render a PUBLIC facing viewuser.html
        Most of the logic for determining PUBLIC and PRIVATE facing is in the jinja2 template code.

        that is how it is coded to handle when you click a username link, it does not return to login, because blogs are supposed
        to be viewed by the public without needing to log in.

        Lastly if a user id is invalid it will redirect to an error 404 page
        '''

        view_user_id = int(self.request.get('u'))

        try:
            view_user = db.get(user_key(view_user_id))
            view_username = view_user.username
            posts = Post.all().filter('user_id =', view_user_id).order('-date_modified')

            u = self.current_user()
            if u:
                # PUBLIC view, user logged in, 
                # PRIVATE view, if jinja2 template code determines that view_username is the same as user_logged in
                self.render('viewuser.html',
                    posts = posts,
                    user_logged = u.username,
                    view_username = view_username,
                    user_id_logged = u.key().id())
            else:
                # PUBLIC view, no user logged in
                self.render('viewuser.html',
                    posts = posts,
                    user_logged = None,
                    view_username = view_username)
        except Exception as e:
            # if the parameters have been tampered, generate error message and redirect to 404error.html
            self.render('404error.html', message = str(e))

class NewPost(Handler):
    def get(self):
        u = self.current_user()
        if u:
            self.render('newpost.html', user_logged = u.username, user_id_logged = u.key().id())
        else:
            # if /newpost was added in the url by a logged out user, they will be redirected to the login page 
            self.redirect('/login')

    def post(self):
        subject = self.request.get('subject') or None
        content = self.request.get('content') or None
        keywords = self.request.get('keywords') or None
        pic = self.request.get('pic') or None
        u = self.current_user()
        if u:
            username = u.username
            try:
                if subject and content:
                    if pic:
                        # clean up URL
                        pic = bleach.clean(pic)
                        # check if pic is an imgur link otherwise return None
                        pic = imageCheck(pic)

                    p = Post(parent = u.key(),
                        user_id = u.key().id(),
                        subject = subject,
                        content = content,
                        keywords = keywords,
                        pic = pic,
                        likes = 0)
                    p.put()
                    self.redirect('/view?p=%s&u=%s' % (p.key().id(), u.key().id()))
                else:
                    self.render('newpost.html',
                        user_logged = u.username,
                        user_id_logged = u.key().id(),
                        message = 'Please include both subject and content')

            except Exception as e:
                self.render('404error.html', message = str(e))
        else:
            # user is not logged in, redirect
            self.redirect('/login')


class EditPost(Handler):
    def get(self):
        post_id = int(self.request.get('pid'))
        u = self.current_user()
        if u:
            try:
                postkey = post_key(post_id, u.key())
                post = db.get(postkey)
                user_id_logged = u.key().id()
                if post.user_id == user_id_logged:
                    self.render('editpost.html',
                        user_logged = u.username,
                        user_id_logged = user_id_logged,
                        post_id = post_id,
                        post = post)
                else:
                    self.render('404error.html', message = 'Error: you are not authorized to edit this post')
            except Exception as e:
                self.render('404error.html', message = 'Error: Unauthorized user')
        else:
            # if user is not logged in he cannot edit the post, redirect to login
            self.redirect('/login')

    def post(self):
        u = self.current_user()
        if u:
            subject = self.request.get('subject') or None
            content = self.request.get('content') or None
            keywords = self.request.get('keywords') or ''
            post_id = int(self.request.get('post_id')) or None
            pic = self.request.get('pic') or None
            user_id_logged = u.key().id()

            if subject and content:
                try:
                    post_key = db.Key.from_path('Post', post_id, parent = u.key())
                    post = db.get(post_key)
                    # check if post owner is the same as user logged in
                    if post.user_id == user_id_logged:
                        post.subject = subject
                        post.content = content
                        post.keywords = keywords
                        if pic:
                            pic = bleach.clean(pic)
                            # check if imgur pic only
                            pic = imageCheck(pic)
                            post.pic = pic
                        post.put()
                        self.redirect('/view?p=%s&u=%s' % (post_id, user_id_logged))
                    else:
                        self.render('404error.html', message = 'Error: you are not authorized to edit this post')
                except:
                    self.render('404error.html', message = 'Error: you are not authorized to edit this post')
            else:
                self.render('editpost.html',
                    user_logged = u.username,
                    user_id_logged = user_id_logged,
                    message = 'Error: please include both subject and content')
        else:
            self.redirect('/login')

class DeletePost(Handler):
    def post(self):
        post_id = int(self.request.get('post_id')) or None
        u = self.current_user()
        if u:
            user_id_logged = u.key().id()

            try:
                # get the post with currently logged in user
                post = db.get(post_key(post_id, u.key()))
                if post.user_id == user_id_logged:
                    post.delete()
                    self.redirect('/viewuserposts?u=%s' % u.key().id())
                else:
                    self.render('404error.html', message = 'Error 1: not authorized to delete this post')
            # if user key does not match with a post id then render error page
            except Exception as e:
                self.render('404error.html', message = 'Error 2 : not authorized to delete this post')
        else:
            self.redirect('/login')

class ViewPost(Handler):
    def get(self):
        '''
        ViewPost has 3 views, PUBLIC, PRIVATE, EDIT COMMENTS. 

        If the user is logged in and the owner of the post being viewed then the 
        edit button will be displayed, it is a PRIVATE view. 

        If the user is also logged in and wants to edit his comment, the same page 
        will be rendered but with an EDIT COMMENT form. 

        If there is no user logged in or the currently logged in user is not the owner of the post
        then it is a PUBLIC view. 

        Please read VIEWPOST.HTML for additional logic in rendering these views. My goal was to make it behave like
        the typical blog site and behave more like a single page application by rendering the same UI but with added components
        and not redirect to a separate page for every comment edit.
        '''
        post_id = int(self.request.get('p')) or None
        user_id = int(self.request.get('u')) or None
        comment_id = self.request.get('c') or None
        message = self.request.get('m') or ''

        user_logged = None # default value to determine if a user is logged in
        user_id_logged = None
        comment = None # default value to decide if a comment is to be edited
        username = None

        try:
            postkey = post_key(post_id, user_key(user_id))
            post = db.get(postkey)
            u = self.current_user()
            if u:
                user_logged = u.username
                user_id_logged = u.key().id()
            if post:
                # check for existing comments
                comments = Comment.all().ancestor(postkey).order('-date_added')
                # check the post's owner username
                post_owner = find_username(post.user_id)
                # comment_id is in the parameter if the previous page's edit comment button was clicked
                if comment_id:
                    commentkey = comment_key(int(comment_id), post_id, user_key(user_id))
                    comment = db.get(commentkey)

                self.render('viewpost.html',
                    post = post,
                    post_owner = post_owner,
                    comments = comments,
                    user_id_logged = user_id_logged,
                    user_logged = user_logged,
                    comment = comment,
                    message = message)
            else:
                self.render('404error.html', message = 'Error: post does not exist')
        except Exception as e:
            self.render('404error.html', message = str(e))

class LikePost(Handler):
    def post(self):
        post_id = int(self.request.get('post_id'))
        user_id = int(self.request.get('user_id'))
        post_username = self.request.get('username')
        message = ''
        u = self.current_user()
        if u:
            # check if user is not liking own post
            if u.username != post_username:
                # check if post was already liked
                likes = Like.all().filter('post_id =', post_id).filter('username =', u.username).get()
                if not likes:
                    # save like
                    postkey = post_key(post_id, user_key(user_id))
                    p = db.get(postkey)
                    p.likes += 1
                    p.put()
                    l = Like(parent = postkey, username = u.username, post_id = post_id)
                    l.put()
                    self.redirect('/view?p=%s&u=%s&#likes' % (post_id, user_id))
                else:
                    message = 'You can only like a post once'
            else:
                message = 'You cannot like your own post'
            self.redirect('/view?p=%s&u=%s&m=%s&#likes' % (post_id, user_id, message))
        else:
            self.redirect('/login')


class NewComment(Handler):
    def post(self):
        new_comment = self.request.get('new_comment') or None
        post_id = int(self.request.get('post_id')) or None
        user_id = int(self.request.get('user_id')) or None

        u = self.current_user()
        if u:
            if new_comment:
                try:
                    comment = Comment(parent = post_key(post_id, user_key(user_id)), username = u.username, content = new_comment, post_id = post_id)
                    comment.put()
                    self.redirect('/view?p=%s&u=%s&#comments' % (post_id, user_id))
                except Exception as e:
                    self.render('404error.html', message = str(e))
            else:
                self.redirect('/view?p=%s&u=%s&m=You must put content in your comment&#comments' % (post_id, user_id))
        else:
            self.redirect('/login')

class EditComment(Handler):
    def post(self):
        comment_id = int(self.request.get('comment_id'))
        post_id = int(self.request.get('post_id'))
        user_id = int(self.request.get('user_id'))
        edited_content = self.request.get('edited_content') or None
        if edited_content:         
            u = self.current_user()
            if u:
                try:
                    commentkey = comment_key(comment_id, post_id, user_key(user_id))
                    comment = db.get(commentkey)
                    # check if comment owner and logged in user is the same
                    if comment.username == u.username:
                        comment.content = edited_content
                        comment.put()
                        self.redirect('/view?p=%s&u=%s&#comments' % (post_id, user_id))
                    else:
                        self.render('404error.html', message = 'Error: you are not authorized to edit this comment')
                except Exception as e:
                    self.render('404error.html', message = str(e))
            else:
                self.redirect('/login')
        else:
            self.redirect('/view?p=%s&u=%s&c=%s&m=Comment cannot be blank&#comments' % (post_id, user_id, comment_id))

class DeleteComment(Handler):
    def post(self):
        comment_id = int(self.request.get('comment_id'))
        post_id = int(self.request.get('post_id'))
        # user_id can be current viewed post's user or currently logged in user 
        user_id = int(self.request.get('user_id'))
        u = self.current_user()
        if u:
            try:
                commentkey = comment_key(comment_id, post_id, user_key(user_id))
                comment = db.get(commentkey)
                if comment.username == u.username:
                    comment.delete()
                    self.redirect('/view?p=%s&u=%s&#comments' % (post_id, user_id))
                else:
                    self.render('404error.html', message = 'Error: you are not authorized to delete this comment')
            except Exception as e:
                self.render('404error.html', message = str(e))
        else:
            self.redirect('/login')

# main page
class MainHandler(Handler):
    def get(self):
        u = self.current_user()
        user_logged = None
        user_id_logged = None
        posts = Post.all().order('-date_added')

        if u:
            user_logged = u.username
            user_id_logged = u.key().id()

        results = posts.fetch(limit=10)
        # Get updated cursor and store it for the first time for pagination
        post_cursor = posts.cursor()
        memcache.set('post_cursor', post_cursor)

        self.render('front.html',
            user_logged = user_logged,
            user_id_logged = user_id_logged,
            posts = results,
            page_number = 1)

class NextResults(Handler):
    def get(self, page):
        u = self.current_user()
        user_logged = None
        user_id = None
        posts = Post.all().order('-date_added')

        post_cursor = memcache.get('post_cursor')
        if post_cursor:
            posts.with_cursor(start_cursor = post_cursor)
        if u:
            user_logged = u.username
            user_id = u.key().id()

        results = posts.fetch(limit=10)
        # Get updated cursor and store it for next time
        post_cursor = posts.cursor()
        memcache.set('post_cursor', post_cursor)

        self.render('front.html', user_logged = user_logged, user_id = user_id, posts = results, page_number = int(page)+1)


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/page/([0-9]+)', NextResults),
    ('/newpost', NewPost),
    ('/editpost', EditPost),
    ('/deletepost', DeletePost),
    ('/view', ViewPost),
    ('/viewuserposts', ViewUser),
    ('/like', LikePost),
    ('/comment', NewComment),
    ('/editcomment', EditComment),
    ('/deletecomment', DeleteComment),
    ('/signup', SignUp),
    ('/login', Login),
    ('/forgot', Forgot),
    ('/change_pwd', ChangePwd)
], debug=True)
