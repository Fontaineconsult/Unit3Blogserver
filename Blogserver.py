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
		else:
			self.user = None

	def usercookie(self):
		return self.user


	def username(self):
		return self.user.split("|")[0]

	def userrecord(self):
		user_record = db.GqlQuery("Select * FROM User WHERE username = '%s'" % self.user)
		user_record_get = user_record.get()
		return user_record_get

	def check_art(self, post_id):
		check = Art.get_by_id(int(post_id))
		logging.info(check.key().id())
		logging.info(post_id)
	 	return check.key().id() == int(post_id)
		
	def check_comments(self, comment_id):
		check = Comments.get_by_id(int(comment_id))
		logging.info(self.user)
		logging.info(check)
		return check.key().id() == int(comment_id) and check.made_by == self.username()
	
########Front Page/Posts########

class Mainpage(Handler):
		
	def save_user_like(self):

		if verify_user(self.user):
			user_cookie = self.request.cookies.get("user")
			post_id = self.request.get("userlike")
			if self.check_art(post_id):
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

				logging.error = (self.userrecord())
				cur_record = self.userrecord()
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
			logging.info(comment)
			comment_to_edit = int(comment[0])
		else:
			logging.info(comment) 
			comment_to_edit = ""

		if verify_user(self.user):
			logging.info("fart2 %s", comment_to_edit)
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
				if self.check_art(delete_comment):
					comment_to_delete = Comments.get_by_id(int(delete_comment))
					comment_to_delete.delete()
					self.redirect("/mainpage")
				else:
					self.redirect("/mainpage")


			if save_like:

				self.save_user_like()
				self.redirect("/mainpage")

			if save_unlike:
				self.remove_user_like()
				self.redirect("/mainpage")

			if enable_comment_edit:
				logging.info( "fart1 %s", enable_comment_edit)
				self.render_login('a','b','c', enable_comment_edit) 
			
			if submitedit:
				updated_comment = self.request.get("comment")
				if self.check_comments(submitedit):
					comments = Comments.get_by_id(int(submitedit))
					logging.info("id %s", submitedit)
					logging.info("comment %s", updated_comment)
					
					if not comments:
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


############## PROBLEM HERE END ############################

########User Login########
class User_Signup(Handler):

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


######Unused Welcome Page#######	
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

			if verify_user: #user verified
				a = Art(title = title, art = art, created_by = current_user)
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
			new_comment = Comments(comment = comment, made_by = self.username(), post = int(post_id))
			new_comment.put()
			post.comment_key.append(new_comment.key())
			post.put()
			self.redirect("/mainpage")
		else:
			logging.error(post_id)
			logging.error(self.check_art(post_id))
			self.error(404)


class PostEdit(Handler):
	def get(self, post_id):
		if verify_user(self.user): #verified user
			arts = Art.get_by_id(int(post_id))
			if self.username() == arts.created_by: #verified owner
				
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
				if post_to_edit.created_by == self.username():
					post_to_edit.visible = False
					post_to_edit.put()
					self.redirect("/mainpage")
				else:
					self.redirect("/login")

			if edit and self.check_art(post_id): #verified art exists
				post_to_edit = Art.get_by_id(int(post_id))
				if post_to_edit.created_by == self.username():
					content = self.request.get("post-body")
					post_to_edit.art = content
					post_to_edit.put()
					time.sleep(0.5)
					self.redirect("/mainpage")
				else:
					self.redirect("/login")
		else:
			self.redirect("/login")

########Sets cookie for whole site#######

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
 		if self.user == None:	
 			self.response.headers.add_header('Set-Cookie', 'user="";Path=/')
 			self.redirect("/mainpage")
 		else:
 			self.redirect("/mainpage")


app = webapp2.WSGIApplication ([("/", Toplevel),("/mainpage", Mainpage), ("/post", Post), (r"/postview/(\d+)", PostHandler),(r"/postedit/(\d+)", PostEdit), ("/signup", User_Signup), ("/welcome", Welcome), ("/login", User_Login), ("/logout", User_Logout)] , debug=True)

