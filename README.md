# Multi-user Coding Blog project

Welcome to the Mindwelder Blog. This is a multi-user blog platform that is a standard blog but is also web developer friendly because it allows the use of HTML formatting tags to display the blog content. If you are used to writing HTML, then you will feel at ease writing in this blog platform. 

Features :
----------
1. Use the h1, h2, h3, p, b, i, em, ul, li, ol, strong, pre, code tags to highlight code, format your blog the html way.
2. Whitelisted HTML tags for security using the python module Bleach.
3. Uses Google Datastore NoSQL for its database
4. Uses Google App Engine / Gcloud for its backend infrastructure
5. Ability to log in and register securely using hashed cookies, with an option to stay logged in (set for about a year).
6. Post imgur links to your posts for a featured image. This feature will be updated in the future to include other image links
7. Ability to reset password through a security question and answer feature
8. View other users' blog posts, like and comment them. Comments are editable / deletable.
9. Users can only like their posts once, a message informs when they attempt to like a post more than once.
10. Posts are viewable by the public without logging in. viewuser.html jinja2 code defines if editing options are available if a user is logged in
    e.g. if user is looking at his own posts then the editing options are shown
11. Anyone can view a certain user's posts by clicking on his username link on any page. The user (logged in or not) will be redirected to
    viewuser.html which will show the list of posts by the viewer sorted by date modified. An edit / delete button will be shown if the user is
    logged in and is the same user being viewed.
11. Users who tamper with the URL parameters in any way will be redirected to a 404 error page.
12. Homepage utilizes pagination and shows a limit of 10 per page. A link at the bottom goes to the next page until the last 10 posts are shown.

13. Only signed in users can post comments. Users can only edit and delete comments they themselves have made. Please refer to jinja2 template code for
    the logic behind this, not main.py

14. Logged in users can create, edit, or delete blog posts they themselves have created. Users should only be able to like posts once and should not be able 
    to like their own post. Please refer to the jinja2 template code for the logic behind this, not main.py


Access in the web :
-------------------
Access the live blog platform at https://mindwelder-blog.appspot.com


How to run locally :
--------------------
1. Make sure to install the Bleach library: 'pip install bleach'
2. Make sure to install a local Google App Engine development environment, it should include the webapp2 framework, jinja2 templating & datastore NoSQL
3. Using a local Google Cloud platform added to $PATH, run with 'dev_appserver.py .' in the project folder
4. Access the web app at 'localhost:8080' in your browser
5. User interaction should be intuitive, There are login and signup links, etc. etc.


Future Updates :
----------------
1. Ability to Unlike posts
2. More than one security question
3. Choose a Gravatar for your profile
4. Ability to make your own User description and edit it
5. After Udacity review, for security purposes, error messaging will be limited