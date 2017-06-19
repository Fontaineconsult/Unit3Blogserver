import webapp2
import os
import jinja2
import string
import re
import time
import hashlib
import hmac
import random
import logging

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)


"""Security/Hashing"""




def hash_str(s):
	SECRET = 'slowmorunning'
    	return hmac.new(SECRET,s).hexdigest()
def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, h=None):
    if h == None:
        salt = make_salt()
    else:
        salt = h.split("|")[1]
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    test_hash = make_pw_hash(name, pw, h).split("|")[0]
 
    if h.split("|")[0] == test_hash:
        return True

def make_user_hash(username):
	hashed = hashlib.sha256(username).hexdigest()
	return "%s|%s" % (username, hashed)

def verify_user(user_hash):
	test_user = make_user_hash(user_hash.split("|")[0])
	if user_hash == test_user:
		return True

def verify_login_input(string_input, type):
	User_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
	password_re = re.compile(r"^.{3,20}$")
	email_re = re.compile(r"^[\S]+@[\S]+.[\S]+$")

	if type == "username":
		output = User_re.match(string_input)
	elif type == "password":
		output =  password_re.match(string_input)
	elif type == "email":
		output =  email_re.match(string_input)
	if output:
		return string_input
	else:
		return "none"


"""Database"""

class Comments(db.Model):
	comment = db.TextProperty(required =True)
	author = db.StringProperty(required=True)
	post = db.IntegerProperty(required=True)
	made_date = db.DateTimeProperty(auto_now_add=True)



class Art(db.Model):
	title = db.StringProperty(required = True)
	art = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	author = db.StringProperty(required = False)
	vote_points = db.IntegerProperty(required = False, default=0)
	comment_key = db.ListProperty(db.Key)
	visible = db.BooleanProperty(default=True)
	


class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.EmailProperty(required = True)
	liked_posts = db.ListProperty(int)




class Utils(webapp2.RequestHandler):
	"""Handler Utilities"""

	def usercookie(self):
		return self.user

	def username(self):
		return self.user.split("|")[0]


	def check_art(self, post_id):
		check = Art.get_by_id(int(post_id))
	 	return check
		
	def check_comments(self, comment_id):
		check = Comments.get_by_id(int(comment_id))
		return check.key().id() == int(comment_id) and check.author == self.username()




class Handler(Utils):
	"""Basic Handler"""
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))
	


	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.request.cookies.get("user")


		if uid != None:
			if verify_user(uid):
	
				self.user = uid
			else:
				self.user = ""
		else:
			self.user = None

		current_user = self.userrecord()
		if current_user != None:
			if current_user.username != self.user:
				self.redirect('login')

	def userrecord(self):
			user_record = db.GqlQuery("Select * FROM User WHERE username = '%s'" % self.user)
			user_record_get = user_record.get()
			return user_record_get
	
	


class Mainpage(Handler):
	"""Front Page/Posts"""
	def save_user_like(self):

		if verify_user(self.user):
			user_cookie = self.request.cookies.get("user")
			post_id = self.request.get("userlike")
			user_record_get = self.userrecord()
			if self.check_art(post_id) and user_record_get:
				liked_post = Art.get_by_id(int(post_id))
				if int(post_id) not in user_record_get.liked_posts and liked_post.author != self.username():
					user_record_get.liked_posts.append(int(post_id))
					user_record_get.put()
					liked_post.vote_points += 1
					liked_post.put()
			else:
				self.redirect("/login")
		else:
			self.redirect("/login")

	def remove_user_like(self):

		if verify_user(self.user):
			comment_like_to_unlike_form = self.request.get("userunlike")
			if self.check_art(comment_like_to_unlike_form):#checks art
				unliked_post = Art.get_by_id(int(comment_like_to_unlike_form))
				unliked_post.vote_points = unliked_post.vote_points - 1
				unliked_post.put()
				cur_record = self.userrecord()
				logging.info(cur_record.username)
				cur_record.liked_posts.remove(int(comment_like_to_unlike_form))
				cur_record.put()
			else:
				self.redirect("/login")
		else:
			self.redirect("/login")


	def render_login(self, title="", art="", error="", *comment):

		arts = db.GqlQuery("Select * FROM Art ORDER BY vote_points DESC")
		comments = db.GqlQuery("Select * FROM Comments")
		user_cookie = self.request.cookies.get("user")
		cur_user = db.GqlQuery("Select * FROM User WHERE username = '%s'" % self.user)
		userdata = cur_user.get()
		if comment:
			comment_to_edit = int(comment[0])
		else:
			
			comment_to_edit = ""

		if verify_user(self.user):
			
			self.render("mainpage.html",title=title, art=art, error=error, arts=arts, comments=comments, userdata=userdata, username=self.username(), comment_edit=comment_to_edit)
		else:
			self.redirect("/login")
		
 	def get(self):
		self.render_login() 

	def post(self):

		delete_comment = self.request.get("commentdelete")
		save_like = self.request.get("userlike")
		save_unlike = self.request.get("userunlike")
		enable_comment_edit = self.request.get("enableedit")
		submitedit = self.request.get("submitedit")
		canceledit = self.request.get("canceledit")

		if verify_user(self.user):

			if delete_comment:
				
				comment_to_delete = Comments.get_by_id(int(delete_comment))
				if not comment_to_delete is None and comment_to_delete.author == self.username():
					comment_to_delete.delete()
					self.redirect("/mainpage")
				else:
					self.redirect("/login")


			if save_like:

				self.save_user_like()
				self.redirect("/mainpage")

			if save_unlike:
				self.remove_user_like()
				self.redirect("/mainpage")

			if enable_comment_edit:
				
				self.render_login('a','b','c', enable_comment_edit) 
			
			if submitedit:
				updated_comment = self.request.get("comment")
				if self.check_comments(submitedit):
					comments = Comments.get_by_id(int(submitedit))
			
					if not comments or comments.author != self.username():
						return self.redirect('login')
					comments.comment = updated_comment
					comments.put()
					self.redirect("/mainpage")
				else:
					self.error(404)

			if canceledit:
				self.redirect("/mainpage")

		else:
			self.redirect("/login")



class User_Signup(Handler):
	"""User Login"""

 	def get(self):
		if verify_user(self.user):
			self.response.headers.add_header('Set-Cookie', 'user='';Path=/')
			self.render("signup.html")

		else:
			self.render("signup.html")
	def post(self):
		
		fullname = verify_login_input(self.request.get("fullname"), type = "username")
		password = verify_login_input(self.request.get("Password"), type = "password")
		passwordv = verify_login_input(self.request.get("verifyp"), type = "password")
		email = verify_login_input(self.request.get("email"), type = "email")

		if fullname != "none" and password != "none" and email != "none" and password == passwordv:

			user_hash = make_user_hash(fullname)
			pass_hash = make_pw_hash(fullname, password)

			user_check = db.GqlQuery("Select * FROM User WHERE username = '%s'" % user_hash)
			if not user_check.get():


				new_user = User(username = user_hash, password = pass_hash, email = email)
				new_user.put()
				self.response.headers.add_header('Set-Cookie', 'user=%s;Path=/' % str(user_hash))
				time.sleep(1)	
				self.redirect("/welcome")

			else:
				user_exists = "This user name already exists"
				self.render("signup.html", error = user_exists)
		if fullname == "none" or password == "none" or email == "none" or password != passwordv:

			self.render("signup.html", fullname = fullname, password = password, email = email, passwordv = "nomatch", loginpage = True)


class User_Login(Handler):
	def get(self):
		if verify_user(self.user):
			self.response.headers.add_header('Set-Cookie', 'user="";Path=/')
			self.render("userlogin.html", loginpage = True)
		else:
			self.render("userlogin.html", loginpage = True)
	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")

		input_user_hash = make_user_hash(username)

		userrequest = db.GqlQuery("Select * FROM User WHERE username = '%s'" % input_user_hash)
		req = userrequest.get()
		if req:

			req_user = req.username
			req_pass = req.password
			req_id = req.key().id()
			
			input_pass_hash = make_pw_hash(username, password, req_pass)

			if input_pass_hash == req_pass:
				self.response.headers.add_header('Set-Cookie', 'user=%s;Path=/' % str(req_user))
				self.redirect("/welcome")
			else:
				error = "Login and Pass Do not Match"
				self.render("userlogin.html", pass_error = error)


		else:
			error = "Username Not Found"
			self.render("userlogin.html", user_error = error)

class User_Logout(Handler):
	def get(self):
		self.render("logout.html")
		self.response.headers.add_header('Set-Cookie', 'user='';Path=/')
		time.sleep(3)
		self.redirect("/login")



class Welcome(Handler):
	"""Welcome Page"""
	def get(self):
		
		if verify_user(self.user):

		 	self.render("welcome.html", username = self.username())
		 	time.sleep(2)
		 	self.redirect("/mainpage")
		else:
			self.redirect("/signup")



		
class Post(Handler):
	"""Blog Posts Creating and Editing"""
	def get(self):
		if verify_user(self.user):
			self.render("post.html", username = self.username())
		else:
			self.redirect("/login")

	def post(self):
		current_user = self.request.cookies.get("user").split("|")[0]
		title = self.request.get("title")
		art = self.request.get("art")
		if title and art:

			if verify_user: #user verified
				a = Art(title = title, art = art, author = current_user)
				a.put()
				time.sleep(1)
				self.redirect("/postview/%s" % a.key().id())
			else:
				self.redirect("/login")	
			
		else:
			error = "Needs a title and a post to continue"
			self.render("post.html", title=title, art=art, error=error, username = self.username())

class PostHandler(Handler):

	def get(self, post_id):

		if Art.get_by_id(int(post_id)): #verified art
			arts = Art.get_by_id(int(post_id))

			if verify_user(self.user): #verified user
				self.render("postview.html", arts=[arts], username = self.username())
			else:
				self.redirect("/login")
		else:
			self.redirect("/mainpage")
	
	def post(self, post_id):


		comment = self.request.get("comment")

		if verify_user(self.user) and self.check_art(post_id): #verified user and art
			post = Art.get_by_id(int(post_id))
			new_comment = Comments(comment = comment, author = self.username(), post = int(post_id))
			new_comment.put()
			post.comment_key.append(new_comment.key())
			post.put()
			self.redirect("/mainpage")
		else:
			self.error(404)


class PostEdit(Handler):
	def get(self, post_id):
		if verify_user(self.user): #verified user
			arts = Art.get_by_id(int(post_id))
			if self.username() == arts.author: #verified owner
				
				self.render("postedit.html", arts=[arts], username = self.username())
			else:
				self.redirect("/mainpage")
		else:
			self.redirect("/login")
	


	def post(self, post_id):
	
		if verify_user(self.user):#verified user
			delete = self.request.get("deletebutt", None)
			edit = self.request.get("submitedit", None)
			
			if delete and self.check_art(post_id): #verified art exists
				post_to_edit = Art.get_by_id(int(post_id))
				if post_to_edit.author == self.username():#verified post owner
					post_to_edit.visible = False
					post_to_edit.put()
					self.redirect("/mainpage")
				else:
					self.redirect("/login")

			if edit and self.check_art(post_id): #verified art exists
				post_to_edit = Art.get_by_id(int(post_id))
				if post_to_edit.author == self.username():#verified post owner
					content = self.request.get("post-body")
					post_to_edit.art = content
					post_to_edit.put()
					time.sleep(0.5)
					self.redirect("/mainpage")
				else:
					self.redirect("/login")
		else:
			self.redirect("/login")



class Toplevel(Handler):
	"""Sets cookie for whole site"""
	def get(self):
		self.response.headers['Content-Type'] = 'text/plain'
 		visits = 0
 		visit_cookie_str = self.request.cookies.get('visits')
 		if visit_cookie_str:
 			cookie_val = check_secure_val(visit_cookie_str)
 			if cookie_val:
 				visits = int(cookie_val)
 		visits += 1
 		new_cookie_val = make_secure_val(str(visits))
 		self.response.headers.add_header('Set-Cookie', 'visits=%s;Path=/' % new_cookie_val)
 		if self.user == None:	
 			self.response.headers.add_header('Set-Cookie', 'user="";Path=/')
 			self.redirect("/mainpage")
 		else:
 			self.redirect("/mainpage")


app = webapp2.WSGIApplication ([("/", Toplevel),("/mainpage", Mainpage), ("/post", Post), (r"/postview/(\d+)", PostHandler),(r"/postedit/(\d+)", PostEdit), ("/signup", User_Signup), ("/welcome", Welcome), ("/login", User_Login), ("/logout", User_Logout)] , debug=True)

