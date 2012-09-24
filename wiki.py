
import urllib

from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers

import os
import re
import random
import hashlib
import hmac
from string import letters
from random import randint

from xml.dom import minidom
import urllib2


import logging


import time

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'putinisterhi'

timeformat = '%a %b %d %H:%M:%S %Y'

def login_check(self):
    cookies = self.request.cookies.get('user_id')
    if cookies:
        return True
    else:
        return False


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

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

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.username + '</b><br>')
    response.out.write(post.content)


########## MAIN PAGE ################


class MainPage(BlogHandler):
  def get(self):
      proverka = login_check(self)
      if proverka == True:
          self.redirect('/blog')
      else:
           self.render("notreg.html")
           return


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

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

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

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
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')






############## CACHE

CACHE = {}

cache_time = 0

def top_posts():
    key = 'top'
    if key in CACHE:
        posts = CACHE[key]
    else:
        global cache_time
        cache_time = time.time()
        logging.error("DB QUERY")
        posts = Post.all().order('-created')            
        posts = posts.run(limit=20)
        posts = list(posts)
        CACHE[key] = posts
    return posts

##### BLOG STUFF

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    username = db.StringProperty()
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    coords = db.GeoPtProperty()
    ip_address = db.StringProperty()
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

 
class BlogFront(BlogHandler):
    def get(self):
        p = self.request.get('p')
        if p:
            x = Post.get_by_id(int(p), parent = blog_key())
            uid = self.read_secure_cookie('user_id')
            username = User.by_id(int(uid)).name
            if x.username == username or username == 'Ribovisor':  
                db.delete(x)
                CACHE.clear()
            self.redirect('/blog')
        else:
            posts = top_posts()

            new_time = time.time() - cache_time
            self.render('front.html', posts = posts, time = "Queried %f seconds ago"%(new_time))

    def post(self):
        content = self.request.get('content')
        if content: 
            uid = self.read_secure_cookie('user_id')
            username = User.by_id(int(uid)).name
            p = Post(parent = blog_key(), username = username, content = content, ip_address = self.request.remote_addr)
            coords = get_coords(self.request.remote_addr)
            if coords:
                p.coords = coords
            p.put()
            CACHE.clear()
            global page_time 
            page_time = time.time()
            posts = top_posts()
            new_time = time.time() - cache_time
            self.redirect('/blog')
        else:
            posts = top_posts()
            new_time = time.time() - cache_time
            self.redirect('/blog')
        



############################################# WIKI ####################

class Wiki(db.Model):
    subject = db.StringProperty()
    content = db.TextProperty(required = True)
    username = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)



class NewWikiPage(BlogHandler):
    def get(self):
        proverka = login_check(self)
        if proverka == True:
            self.render("WikiStart.html")
        else:
            self.redirect('/')

    def post(self):
        content = self.request.get('content')
        path = self.request.get('path')
        if path and content:
            k = db.Key.from_path("path",'/'+path)
            uid = self.read_secure_cookie('user_id')
            username = User.by_id(int(uid)).name
            w = Wiki(parent = k, content = content, username = username, subject = path)
            w.put()
            self.redirect('/'+path)
        else:
            self.render('WikiStart.html')


class EditPage(BlogHandler):
    def get(self, path):
        k = db.Key.from_path("path", path)
        x = Wiki.all().ancestor(k).order("-created").get() 
        proverka = login_check(self)
        if proverka == True:
            if x:
                self.render('EditWiki.html', content = x.content)
            else:
                self.render('EditWiki.html')
        else:
            self.redirect('/')

 
    def post(self, path):
        content = self.request.get('content')
        if content:
            k = db.Key.from_path("path", path)
            uid = self.read_secure_cookie('user_id')
            username = User.by_id(int(uid)).name
            w = Wiki(parent = k, content = content, username = username, subject = path)
            w.put()
            self.redirect(path)
        else:
            self.render('EditWiki.html')
        

class WikiPage(BlogHandler):
    def get(self, path):
        k = db.Key.from_path("path", path)
        version = self.request.get('v')
        if version:
            x = Wiki.get_by_id(int(version), parent = k)
            self.render("new_page.html", text_by_user = x.content, path = path)
        else: 
            x = Wiki.all().ancestor(k).order("-created").get()
            if x:
                self.render("new_page.html", text_by_user = x.content, path = path)
            else:
                proverka = login_check(self)
                if proverka == True:
                    self.redirect('/_edit'+path)
                else:
                    self.redirect('/')


class HistoryPage(BlogHandler):
     def get(self, path):
        k = db.Key.from_path("path", path)
        s = db.GqlQuery("SELECT * FROM Wiki WHERE ANCESTOR IS :1 ", k) 
        self.render("DB.html", subjects = s, paths = path)  

########## Delete ALL #####

class DeleteAll(BlogHandler):
    def get(self):
        db.delete(Post.all()) 
        self.response.out.write("udalit' vse?")

class DeleteHandler(BlogHandler):
    def get(self, path):
        k = db.Key.from_path("path", path)
        x = Wiki.all().ancestor(k)
        if x:
            db.delete(x) 
        self.redirect('/blog')


###### WIKI 10 PAGES

class RecentWiki(BlogHandler):
    def get(self):
        x = Wiki.all().order('-created')
        x = x.run(limit=10)
        self.render('wikipages.html', subjects = x)
        


############ Recent Users

class RecentUsers(BlogHandler):
    def get(self):
        p = list(Post.all())
        points = filter(None, (a.coords for a in p))
        img_url = None
        if points:
            img_url = gmaps_img(points)
        x = User.all()
        self.render('Users.html', subjects = x, img_url = img_url)



########## geolocation

IP_URL = "http://api.ipinfodb.com/v3/ip-city/?key=fb0620d58d37d0dad6bbed62b8ac270c80f5bebcdf941837fd1f29a86cd67ccb&ip="
GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false"

def gmaps_img(points):
    x = GMAPS_URL
    for i in range(len(points)):
        x += '&markers=%d,%d'%(points[i].lat, points[i].lon)
    return x


def get_coords(ip):
    url = IP_URL + ip
    content = None
    try:
        content = urllib2.urlopen(url).read()
    except URLError:
        return
    if content:
       # p = minidom.parseString(content)
       # x = p.getElementsByTagName("gml:coordinates")
       # if x and x[0].childNodes[0].nodeValue:
       #     lon, lat = x[0].childNodes[0].nodeValue.split(',')
        lon, lat = convert(content)        
        #return lat, lon 
        return db.GeoPt(lat, lon)




def convert(data):
   x = data.split(';')
   n = len(x)
   lat = float(x[n-3])
   lon = float(x[n-2])
   return lon, lat
    

###################### GAME

class Game(db.Model):
    name = db.StringProperty(required = True)
    round_game = db.IntegerProperty(required = True)
    wins = db.IntegerProperty(required = True)
    performance = db.FloatProperty(required = True)
  
   
everythings = {}


def new_round(self):
    key = 'round'
    if key in everythings:
        round_game = everythings[key]
    else:
        uid = self.read_secure_cookie('user_id')
        username = User.get_by_id(int(uid), parent = users_key()).name
        k = db.Key.from_path("username", username)
        g = Game.all().ancestor(k).get()
        if g:
            round_game = g.round_game
            wins = g.wins
            performance = g.performance
        else:
            round_game = 1
            wins = 0
            performance = 0.0
            x = Game(parent = k, name = username, round_game = round_game, wins = wins, performance = performance)
            x.put()  
        g = Game.all().ancestor(k).get()
    return g


def truthing():
    key = 'truth'
    if key in everythings:
        truth = everythings[key]
    else:
        truth = randint(1,3)
        everythings[key] = truth
    return truth

def format_perf(data):
    return "{0:.0f}%".format(data*100)


class MontyHall(BlogHandler):
    def get(self):
        truth = truthing()
        choice = self.request.get('v')
        g = new_round(self)
        if choice:
            if int(choice) == truth:
                show = randint(1,3)
                while show == truth:
                    show = randint(1,3)
                ubrat = 6 - truth - show
                self.render('choice_1.html', odin = int(choice), dva = ubrat, round_game = g.round_game, wins = g.wins, performance = format_perf(g.performance))
            else:
                show = randint(1,3)
                while show == int(choice) or show == truth:
                    show = randint(1,3)
                self.render('choice_1.html', odin = int(choice), dva = truth, round_game = g.round_game, wins = g.wins, performance = format_perf(g.performance))
        p = self.request.get('p')
        if p:
            p = int(self.request.get('p'))	
            if p == truth:
                g.round_game += 1
                g.wins += 1
                g.performance = float(g.wins)/float(g.round_game)
                g.put()
                everythings.clear()
                self.render('pobeda.html', odin =truth, round_game = g.round_game, wins = g.wins, performance = format_perf(g.performance))
            if p != truth:
                g.round_game += 1
                g.performance = float(g.wins)/float(g.round_game)
                g.put()
                everythings.clear()
                self.render('proigrish.html',odin =truth, round_game = g.round_game, wins = g.wins, performance = format_perf(g.performance))
        if not p and not choice:
            self.render('game.html', round_game =g.round_game, wins = g.wins, performance = format_perf(g.performance))



class NullMontyHall(BlogHandler):
    def get(self):
        uid = self.read_secure_cookie('user_id')
        username = User.get_by_id(int(uid), parent = users_key()).name
        k = db.Key.from_path("username", username)
        g = Game.all().ancestor(k).get()
        db.delete(g)
        everythings.clear()
        self.redirect('/monty_hall')



class LeaderBoard(BlogHandler):
    def get(self):
        k = Game.all().fetch(100)
        list_of_fame = []
        for i in k:
            x = i.parent_key()
            if x not in list_of_fame:
                list_of_fame.append(x)
        new_list = []
        for i in list_of_fame:
            g = Game.all().ancestor(i).order('-performance').get()
            new_list.append(g)
        dict_of_fame = {}
        sort_list = []
        for i in new_list:
            dict_of_fame[format_perf(i.performance)] = i.name
            sort_list.append(format_perf(i.performance))
        sort_list = sorted(sort_list, reverse=True)
        length = len(sort_list)
        self.render('leaderboard.html', length = length, sort_list = sort_list, dict_of_fame = dict_of_fame)



################# UPLOADER	

class UpHandler(webapp2.RequestHandler):
  def get(self):
    upload_url = blobstore.create_upload_url('/upload')
    self.response.out.write('<html><body>')
    self.response.out.write('<form action="%s" method="POST" enctype="multipart/form-data">' % upload_url)
    self.response.out.write("""Upload File: <input type="file" name="file"><br> <input type="submit"
        name="submit" value="Submit"> </form></body></html>""")

class UploadHandler(blobstore_handlers.BlobstoreUploadHandler):
  def post(self):
    upload_files = self.get_uploads('file')  # 'file' is file upload field in the form
    blob_info = upload_files[0]
    self.redirect('/serve/%s' % blob_info.key())

class ServeHandler(blobstore_handlers.BlobstoreDownloadHandler):
  def get(self, resource):
    resource = str(urllib.unquote(resource))
    blob_info = blobstore.BlobInfo.get(resource)
    self.send_blob(blob_info)

        
        




app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_null/monty_hall', NullMontyHall),
                               ('/monty_hall', MontyHall),
                               ('/monty_hall/stats', LeaderBoard),
                               ('/_del' + PAGE_RE, DeleteHandler),
                               ('/_history' + PAGE_RE, HistoryPage), 
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/new_wiki', NewWikiPage),
                               ('/wiki', RecentWiki),
                               ('/users', RecentUsers),
                               ('/delete_all', DeleteAll),
                               ('/uploads', UpHandler),
                               ('/upload', UploadHandler),
                               ('/serve/([^/]+)?', ServeHandler),
                               (PAGE_RE, WikiPage),
                              ],
                              debug=True)
