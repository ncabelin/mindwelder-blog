from google.appengine.ext import db

class User(db.Model):
    username = db.StringProperty(required = True)
    email = db.StringProperty()
    password = db.StringProperty(required = True)
    security_q = db.StringProperty(required = True)
    security_a = db.StringProperty(required = True)
    salt = db.StringProperty(required = True)

class Post(db.Model):
    user_id = db.IntegerProperty(required = True)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    keywords = db.StringProperty()
    likes = db.IntegerProperty(required = True)
    date_added = db.DateTimeProperty(auto_now_add = True)
    date_modified = db.DateTimeProperty(auto_now = True)
    pic = db.StringProperty()

class Comment(db.Model):
    # the comment owner / user
    username = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    # the post id that had been commented on, not necessarily the user's own post
    post_id = db.IntegerProperty(required = True)
    date_added = db.DateTimeProperty(auto_now_add = True)

class Like(db.Model):
    username = db.StringProperty(required = True)
    post_id = db.IntegerProperty(required = True)
