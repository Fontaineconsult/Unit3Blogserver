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


########Security/Hashing########

User_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
password_re = re.compile(r"^.{3,20}$")
email_re = re.compile(r"^[\S]+@[\S]+.[\S]+$")


SECRET = 'Fartmachine'
def hash_str(s):
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



########Basic Handler########


class Handler(webapp2.RequestHandler):

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
		

	def usercookie(self):
		return self.user


	def username(self):
		return self.user.split("|")[0]

	def userrecord(self):
		user_record = db.GqlQuery("Select * FROM User WHERE username = '%s'" % self.user)
		user_record_get = user_record.get()
		return user_record_get



#######Database#######

class Comments(db.Model):
	comment = db.TextProperty(required =True)
	made_by = db.StringProperty(required=True)
	post = db.IntegerProperty(required=True)
	made_date = db.DateTimeProperty(auto_now_add=True)



class Art(db.Model):
	title = db.StringProperty(required = True)
	art = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	created_by = db.StringProperty(required = False)
	vote_points = db.IntegerProperty(required = False, default=0)
	comment_key = db.ListProperty(db.Key)
	visible = db.BooleanProperty(default=True)
	


class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.EmailProperty(required = True)
	liked_posts = db.ListProperty(int)


########Front Page/Posts########
class Mainpage(Handler):

	def save_user_like(self):
		user_cookie = self.request.cookies.get("user")

		post_id = self.request.get("userlike")
		post_id = int(post_id)
		liked_post = Art.get_by_id(int(post_id))

		user_record = db.GqlQuery("Select * FROM User WHERE username = '%s'" % user_cookie)
		user_record_get = user_record.get()

		for stored_cookie in user_record_get.liked_posts:
		
			if post_id == stored_cookie or liked_post.created_by == self.username():
				break
		else:

			user_record_get.liked_posts.append(int(post_id))
			user_record_get.put()
			
		
			liked_post.vote_points += 1
			liked_post.put()
		
	def remove_user_like(self):
		comment_like_to_unlike_form = self.request.get("userunlike")
		unliked_post = Art.get_by_id(int(comment_like_to_unlike_form))
		unliked_post.vote_points = unliked_post.vote_points - 1
		unliked_post.put()

		logging.error = (self.userrecord())
		cur_record = self.userrecord()
		cur_record.liked_posts.remove(int(comment_like_to_unlike_form))
		cur_record.put()


	def render_login(self, title="", art="", error=""):
		arts = db.GqlQuery("Select * FROM Art ORDER BY vote_points DESC")
		comments = db.GqlQuery("Select * FROM Comments")
		user_cookie = self.request.cookies.get("user")
		cur_user = db.GqlQuery("Select * FROM User WHERE username = '%s'" % self.user)
		userdata = cur_user.get()
	
	
		if verify_user(self.user):

			
			self.render("mainpage.html",title=title, art=art, error=error, arts=arts, comments=comments, userdata = userdata, username = self.username())
		else:
			self.redirect("/login")
		
 	def get(self):
		self.render_login() 

	def post(self):

		delete_comment = self.request.get("commentdelete")
		save_like = self.request.get("userlike")
		save_unlike = self.request.get("userunlike")

		if delete_comment:
			comment_to_delete = Comments.get_by_id(int(delete_comment))
			comment_to_delete.delete()
			self.redirect("/mainpage")

		if save_like:

			self.save_user_like()
			self.redirect("/mainpage")

		if save_unlike:
			self.remove_user_like()
			self.redirect("/mainpage")


########User Login########
class User_Signup(Handler):

 	def get(self):
		self.render("signup.html")
		namer = self.request.get("fullname")	


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

			self.render("signup.html", fullname = fullname, password = password, email = email, passwordv = "nomatch")


class User_Login(Handler):
	def get(self):
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
		
			input_pass_hash = make_pw_hash(username, password, req_pass)

			logging.error ("req_pass = %s and input_pass_hash = %s" % (req_pass, input_pass_hash))
			#logging.error ("req_user = %s and input_user_hash = %s" % (req_user, input_user_hash))

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

	def get(self):
		
		if verify_user(self.user):

		 	self.render("welcome.html", username = self.username())
		 	time.sleep(3)
		 	self.redirect("/mainpage")
		else:
			self.redirect("/signup")


########Blog Posts########
		
class Post(Handler):
	

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
			a = Art(title = title, art = art, created_by = current_user)
			a.put()
			time.sleep(1)
			self.redirect("/postview/%s" % a.key().id())
		
		else:
			error = "Fill it all out dumbwag"
			self.render("post.html", title=title, art=art, error=error, username = self.username())

class PostHandler(Handler):
	def get(self, post_id):
		if verify_user(self.user):
			arts = Art.get_by_id(int(post_id))
			self.render("postview.html", arts=[arts], username = self.username())
		else:
			self.redirect("/login")
	
	def post(self, post_id):
		comment = self.request.get("comment")

		post = Art.get_by_id(int(post_id))
		new_comment = Comments(comment = comment, made_by = self.username(), post = int(post_id))
		new_comment.put()
		post.comment_key.append(new_comment.key())
		post.put()
	
		self.redirect("/mainpage")


class PostEdit(Handler):
	def get(self, post_id):
		if verify_user(self.user):
			arts = Art.get_by_id(int(post_id))
			if self.username() == arts.created_by:
				
				self.render("postedit.html", arts=[arts], username = self.username())
			else:
				self.redirect("/mainpage")
		else:
			self.redirect("/login")
	


	def post(self, post_id):
	

		
		
		delete = self.request.get("deletebutt", None)
		edit = self.request.get("submitedit", None)
		
		if delete:
			post_to_edit = Art.get_by_id(int(post_id))
			post_to_edit.visible = False
			post_to_edit.put()
			self.redirect("/mainpage")
	
		if edit:
			post_to_edit = Art.get_by_id(int(post_id))
			content = self.request.get("post-body")
			post_to_edit.art = content
			post_to_edit.put()
			time.sleep(0.5)
			self.redirect("/mainpage")



########

class Toplevel(Handler):
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




app = webapp2.WSGIApplication ([("/", Toplevel),("/mainpage", Mainpage), ("/post", Post), (r"/postview/(\d+)", PostHandler),(r"/postedit/(\d+)", PostEdit), ("/signup", User_Signup), ("/welcome", Welcome), ("/login", User_Login), ("/logout", User_Logout)] , debug=True)

