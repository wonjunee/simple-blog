import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'helloworld'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Make User info more secure
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

# Check if the user info is correct
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # Every request calls this initialize
    # This function set the user parameter.
    # This allows the blog to know if some user is logged in
    # or none is logged in. If none then it shows "signup" link
    # On the base page.
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

# Creating Hash for password
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# Check the hash pw is same as the original one.
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# don't have to do this but this will organize the database
# when you have multiple of them
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    # This is called a decorater.
    # cls = class -> User not. self the class itself.
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    # Create a new user in User class
    # It's important to use @classmethod because
    # it allows to refer to User class itself
    # instead of a particular instance of User class.
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)

    gre_words = db.IntegerProperty(required = True)
    gre_essays = db.IntegerProperty(required = True)
    gre_verbal = db.IntegerProperty(required = True)
    gre_math = db.IntegerProperty(required = True)
    school_research = db.IntegerProperty(required = True)
    sop = db.IntegerProperty(required = True)
    other = db.IntegerProperty(required = True)

    gre_words_more = db.TextProperty()
    gre_essays_more = db.TextProperty()
    gre_verbal_more = db.TextProperty()
    gre_math_more = db.TextProperty()
    school_research_more = db.TextProperty()
    sop_more = db.TextProperty()
    other_more = db.TextProperty()
    
    created = db.DateTimeProperty(auto_now_add = True)

    username = db.StringProperty(required = True)

    total = db.IntegerProperty()

    def render(self):
        # self._render_text = self.content.replace('\n', '<br>')
        self.total = self.gre_words + self.gre_essays + self.gre_verbal + self.gre_math + self.school_research + self.sop + self.other
        return render_str("post.html", p = self)

    @property
    def comments(self):
        return Comment.all().filter("post = ", str(self.key().id()))

class BlogFront(BlogHandler):
	def get(self):
		posts = Post.all().order('-created')
		self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

def checklist(todo):
    gre_words = 0
    gre_essays = 0
    gre_verbal = 0
    gre_math = 0
    school_research = 0
    sop = 0
    other = 0
    if "gre-words" in todo:
        gre_words = 1
    if "gre-essays" in todo:
        gre_essays = 1
    if "gre-verbal" in todo:
        gre_verbal = 1
    if "gre-math" in todo:
        gre_math = 1
    if "school-research" in todo:
        school_research = 1
    if "sop" in todo:
        sop = 1
    if "other" in todo:
        other = 1
    return [gre_words, gre_essays, gre_verbal, gre_math, school_research, sop, other]

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')

        todo = self.request.get('todo', allow_multiple=True)
        gre_words, gre_essays, gre_verbal, gre_math, school_research, sop, other = checklist(todo)
        
        username = self.user.name

        gre_words_more = self.request.get('gre-words')
        gre_essays_more = self.request.get('gre-essays')
        gre_verbal_more = self.request.get('gre-verbal')
        gre_math_more = self.request.get('gre-math')
        school_research_more = self.request.get('school-research')
        sop_more = self.request.get('sop')
        other_more = self.request.get('other')

        if subject:
            p = Post(parent = blog_key(), subject = subject,
                username = username,
                gre_words = gre_words,
                gre_essays = gre_essays,
                gre_verbal = gre_verbal,
                gre_math = gre_math,
                school_research = school_research,
                sop = sop,
                other = other,
                gre_words_more = gre_words_more,
                gre_essays_more = gre_essays_more,
                gre_verbal_more = gre_verbal_more,
                gre_math_more = gre_math_more,
                school_research_more = school_research_more,
                sop_more = sop_more,
                other_more = other_more)

            p.put()
            self.redirect('/%s' % str(p.key().id()))
        else:
            error = "subject, please!"
            self.render("newpost.html", subject=subject, username = username,  error=error)

# A class for editing a post
class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user:
        	if self.user.name == post.username:
	            self.render("editpost.html", post = post, subject=post.subject,
                    gre_words_more = post.gre_words_more,
                    gre_essays_more = post.gre_essays_more,
                    gre_verbal_more = post.gre_verbal_more,
                    gre_math_more = post.gre_math_more,
                    school_research_more = post.school_research_more,
                    sop_more = post.sop_more,
                    other_more = post.other_more,
                    )
	        else:
	        	self.redirect("/notallowed0")
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')

        username = self.user.name

        todo = self.request.get('todo', allow_multiple=True)
        gre_words, gre_essays, gre_verbal, gre_math, school_research, sop, other = checklist(todo)

        gre_words_more = self.request.get('gre-words')
        gre_essays_more = self.request.get('gre-essays')
        gre_verbal_more = self.request.get('gre-verbal')
        gre_math_more = self.request.get('gre-math')
        school_research_more = self.request.get('school-research')
        sop_more = self.request.get('sop')
        other_more = self.request.get('other')


        if subject:
            # find a post from the database
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            p = db.get(key)

            # Update the post
            p.subject = subject
            p.username = username

            p.gre_words = gre_words
            p.gre_essays = gre_essays
            p.gre_verbal = gre_verbal
            p.gre_math = gre_math
            p.school_research = school_research
            p.sop = sop
            p.other = other

            p.gre_words_more = gre_words_more
            p.gre_essays_more = gre_essays_more
            p.gre_verbal_more = gre_verbal_more
            p.gre_math_more = gre_math_more
            p.school_research_more = school_research_more
            p.sop_more = sop_more
            p.other_more = other_more

            p.put()

            # Redirect to the single post page with an updated post
            self.redirect('/%s' % str(p.key().id()))

        else:
            error = "subject, please!"
            self.render("editpost.html", subject=subject,
                    gre_words_more = gre_words_more,
                    gre_essays_more = gre_essays_more,
                    gre_verbal_more = gre_verbal_more,
                    gre_math_more = gre_math_more,
                    school_research_more = school_research_more,
                    sop_more = sop_more,
                    other_more = other_more,
                    error = error)

# A class for deleting a post
class DeletePost(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if self.user:
			if self.user.name == post.username:
			    self.render("deletepost.html", p = post, subject=post.subject,
                    gre_words_more = post.gre_words_more,
                    gre_essays_more = post.gre_essays_more,
                    gre_verbal_more = post.gre_verbal_more,
                    gre_math_more = post.gre_math_more,
                    school_research_more = post.school_research_more,
                    sop_more = post.sop_more,
                    other_more = post.other_more,
                    )
			else:
				self.redirect("/notallowed0")
		else:
		    self.redirect("/login")

	def post(self, post_id):
		if not self.user:
			self.redirect('/')

		delete_choice = self.request.get('q')
		username = self.user.name

		if delete_choice == "yes":
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)
			post.delete()
			self.redirect('/deleted0')
		elif delete_choice == "no":
			self.redirect('/')

# A class for liking a post
class LikePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            # The writer cannot like his own post
            if self.user.name == post.username:
                self.redirect('/')
            else:
                like_number = int(post.like_number)
                if not post.like_users:
                    users = []
                else:
                    users = post.like_users.split(",")

                if self.user.name in users:
                    like_number -= 1
                    users.remove(self.user.name)
                    like_url = "/like0"
                else:
                    like_number += 1
                    users.append(self.user.name)
                    like_url = "/like1"

                users = ",".join(users)
                post.like_number  = str(like_number)
                post.like_users = users
                post.put()

                posts = Post.all().order('-created')

                self.render('front.html', posts = posts)
                self.redirect(like_url)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            # Create a new User instance
            u = User.register(self.username, self.password, self.email)

            # Insert into the database
            u.put()

            # login is from BlogHandler class
            # It creates a secure cookie for a user
            self.login(u)

            # Redirect to the welcome page
            self.redirect('/welcome')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        if username == "wonjunee" or username == "yuri":
            u = User.login(username, password)
            if u:
                self.login(u)
                self.redirect('/')
            else:
                msg = 'Invalid login'
                self.render('login-form.html', error = msg)
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

# DB for comments
class Comment(db.Model):
    post = db.StringProperty(required = True)
    comment = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    username = db.StringProperty(required = True)

class NewComment(BlogHandler):
    def get(self,post_id):
        if not self.user:
            return self.redirect("/login")
        post = Post.get_by_id(int(post_id), parent=blog_key())
        subject = post.subject
        self.render(
            "newcomment.html",
            subject=subject,
            pkey=post.key(),
            p = post
            )
                    # gre_words_more = post.gre_words_more,
            # gre_essays_more = post.gre_essays_more,
            # gre_verbal_more = post.gre_verbal_more,
            # gre_math_more = post.gre_math_more,
            # school_research_more = post.school_research_more,
            # sop_more = post.sop_more,
            # other_more = post.other_more,

    def post(self, post_id):
        if self.user:
            key = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            if not self.user:
                return self.redirect("login")
            comment = self.request.get("comment")

            if comment:
                # check how author was defined
                username = self.user.name
                c = Comment(
                    comment=comment,
                    post=post_id,
                    parent=self.user.key(),
                    username=username)
                c.put()
                self.redirect("/%s" % str(post_id))

            else:
                error = "please comment"
                self.render(
                    "newcomment.html",
                    subject=post.subject,
                    pkey=post.key(),
                    p = post,
                    # gre_words_more = post.gre_words_more,
                    # gre_essays_more = post.gre_essays_more,
                    # gre_verbal_more = post.gre_verbal_more,
                    # gre_math_more = post.gre_math_more,
                    # school_research_more = post.school_research_more,
                    # sop_more = post.sop_more,
                    # other_more = post.other_more,
                    error=error)
        else:
            self.redirect("/login")


# A class for editing a comment
class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=self.user.key())
        comment = db.get(key)
        if self.user:
            if not comment:
                self.redirect('/notallowed1')
            else:
                self.render("editcomment.html", comment=comment.comment)
        else:
            self.redirect("/login")

    def post(self, post_id, comment_id):
        if not self.user:
            self.redirect('/')

        usercomment = self.request.get('comment')

        if usercomment:
            key = db.Key.from_path('Comment', int(comment_id), parent=self.user.key())
            comment = db.get(key)
            comment.comment = usercomment
            comment.put()

            self.redirect('/%s' %post_id)
        else:
            error = "comment, please!"
            self.render("editcomment.html", comment=usercomment, error=error)

# A class for deleting a comment
class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=self.user.key())
        comment = db.get(key)

        if self.user:
            if comment:
                self.render("deletecomment.html", comment=comment.comment)
            else:
                self.redirect("/notallowed1")
        else:
            self.redirect("/login")

    def post(self, post_id, comment_id):
        if not self.user:
            self.redirect('/')

        delete_choice = self.request.get('q')

        if delete_choice == "yes":
            key = db.Key.from_path('Comment', int(comment_id), parent=self.user.key())
            comment = db.get(key)
            comment.delete()
            self.redirect('/deleted1')
        elif delete_choice == "no":
            self.redirect('/')

# This class is for the page that alerts users if
# they attempt to edit posts that are written by others
class NotAllowed(BlogHandler):
    def get(self, post_comment):
        if post_comment == "0":
            post_comment = "Post"
        else:
            post_comment = "Comment"
        self.render('notallowed.html', type=post_comment)

# This class confirms the deletion of posts
class Deleted(BlogHandler):
    def get(self, post_comment):
        if post_comment == "0":
            post_comment = "Post"
        else:
            post_comment = "Comment"
        self.render('deleted.html', post_comment=post_comment)

# A class for summary
class Summary(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        gre_words = 0
        gre_essays = 0
        gre_verbal = 0
        gre_math = 0
        school_research = 0
        sop = 0
        other = 0
        for post in posts:
            gre_words += post.gre_words
            gre_essays += post.gre_essays
            gre_verbal += post.gre_verbal
            gre_math += post.gre_math
            school_research += post.school_research
            sop += post.sop
            other += post.other

        self.render('summary.html', posts = posts, 
            gre_words = gre_words,
            gre_essays = gre_essays,
            gre_verbal = gre_verbal,
            gre_math = gre_math,
            school_research = school_research,
            sop = sop,
            other = other)

app = webapp2.WSGIApplication([
                               ('/?', BlogFront),
                               ('/([0-9]+)', PostPage),
                               ('/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/([0-9]+)/edit', EditPost),
                               ('/([0-9]+)/delete', DeletePost),
                               ('/([0-9]+)/comment/?', NewComment),
                               ('/([0-9]+)/comment/([0-9]+)/edit', EditComment),
                               ('/([0-9]+)/comment/([0-9]+)/delete', DeleteComment),
                               ('/notallowed([0-9])', NotAllowed),
                               ('/deleted([0-9])', Deleted),
                               ('/summary', Summary)
                               ],
                              debug=True)
