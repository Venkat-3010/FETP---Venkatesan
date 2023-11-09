import json
import os
import sqlite3
#import pathlib

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

from flask import Flask,redirect,request,url_for,session
#from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from flask_login import(
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
    )

from oauthlib.oauth2 import WebApplicationClient
import requests

from db import init_db_command
from user import User

app = Flask(__name__)
app.secret_key = "your_secret_key" or os.urandom(24)

# Google OAuth 2.0 configuration
GOOGLE_CLIENT_ID = "GOOGLE_CLIENT_ID"
GOOGLE_CLIENT_SECRET = "GOOGLE_CLIENT_SECRET"
SCOPES = ["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"]

GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.unauthorized_handler
def unauthorized():
    return "You must be logged in to access this content.", 403

try:
    init_db_command()
except sqlite3.OperationalError:
    pass

client = WebApplicationClient(GOOGLE_CLIENT_ID)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route('/')
def index():
    if current_user.is_authenticated:
        return (
            '<div><img src="{}" alt="Google profile picture"></img>'
            '<p>Profile Picture</p></div>'
            '<p>Hello {}</p><a class="button" href="/logout">Logout</a>'
            '<p>You are signed in with the email {}</p>'
                ).format(current_user.profile_pic, current_user.name, current_user.email)


    else:
        return '<a class="button" href="/login"><center>Google Login</center></a>'

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(
    "client_secret.json",
    scopes=SCOPES,
    redirect_uri=request.base_url + "/callback"
    )
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/login/callback')
def callback():
    code = request.args.get("code")

    google_provider_cfg = get_google_provider_cfg()

    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code,
    )

    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
    )

    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg['userinfo_endpoint']

    uri,headers,body = client.add_token(userinfo_endpoint)

    userinfo_response = requests.get(uri,headers=headers,data=body)
    print(userinfo_response.json())

    if userinfo_response.json().get('email_verified'):
        unique_id = userinfo_response.json()['sub']
        users_email = userinfo_response.json()['email']
        picture = userinfo_response.json()['picture']
        users_name = userinfo_response.json()['given_name']
    else:
        return "User email not available or not verified", 400
    
    user = User(
        id_ = unique_id,name=users_name,email=users_email,profile_pic=picture
    )

    if not User.get(unique_id):
        User.create(unique_id,users_name,users_email,picture)

    login_user(user)

    return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

if __name__ == "__main__":
    app.run(debug=True)
