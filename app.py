from flask import *
from requests_oauthlib import OAuth2Session
from flask.json import jsonify
import os, datetime, functools, re, urllib
from flask import (Flask, abort, flash, Markup, redirect, render_template,
                   request, Response, session, url_for)
from markdown import markdown
from markdown.extensions.codehilite import CodeHiliteExtension
from markdown.extensions.extra import ExtraExtension
from micawber import bootstrap_basic, parse_html
from micawber.cache import Cache as OEmbedCache
from peewee import *
from playhouse.flask_utils import FlaskDB, get_object_or_404, object_list
from playhouse.sqlite_ext import *

#creates the path for the app location. 
APP_DIR = os.path.dirname(os.path.realpath(__file__))
#sets the database location using the applocation path above. 
DATABASE = 'sqliteext:///%s' % os.path.join(APP_DIR, 'blog.db')
app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key = os.urandom(24)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

#flask-db wrapper config
flask_db = FlaskDB(app)
database = flask_db.database

#github auth app info. 
client_id = "05694693af7bf2f9160a"
client_secret = "b6b413c9ec859f35e77411ba4d3d4b875b5f4a73"
authorization_base_url = 'https://github.com/login/oauth/authorize'
token_url = "https://github.com/login/oauth/access_token"

#database models 
class Entry(flask_db.Model):
    title = CharField()
    slug = CharField(unique=True)
    content = TextField()
    published = BooleanField(index=True)
    timestamp = DateTimeField(default=datetime.datetime.now, index=True)

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = re.sub('[^\w]+', '-', self.title.lower())
        ret = super(Entry, self).save(*args, **kwargs)

#begin the definition of the routes etc. 
@app.route('/')
def hello_world():
    return render_template('index.html')

@app.route("/home")
def blog():
    return render_template('blog.html')

@app.route("/login")
def demo():
    """Step 1: User Authorization.

    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """
    github = OAuth2Session(client_id)
    authorization_url, state = github.authorization_url(authorization_base_url)

    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    return redirect(authorization_url)

#OAuth routes being made. 

@app.route("/callback", methods=["GET"])
def callback():
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """

    github = OAuth2Session(client_id, state=session['oauth_state'])
    token = github.fetch_token(token_url, client_secret=client_secret,
                               authorization_response=request.url)

    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.
    session['oauth_token'] = token
    r = github.get('https://api.github.com/user')
    r = r.json()
    session['userName'] = r['login']
    # print(session['userName'])
    return redirect(url_for('hello_world'))

#handles the clearing of the session cookie data. Then redirects back to blank page.
@app.route("/logout")
def logout():
    if session['oauth_token']:
        session.clear()
        return redirect(url_for('hello_world'))