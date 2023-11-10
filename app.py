import json
import os
import sqlite3
#import pathlib

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

from flask import Flask,redirect,request,url_for,session,render_template
from datetime import datetime
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
GOOGLE_CLIENT_ID = "1077328913313-4eve4i31ebetnijksh6u53jfm9g20fti.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
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
         current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
         return render_template('index.html', user_info=current_user, current_time=current_time)
    else:
         return '<center><a class="button" align="center" href="/login">Google Login</a></center>'

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

@app.route('/display_diamond', methods=['POST'])
@login_required
def display_diamond():
    num_lines = int(request.form['num_lines'])
    diamond_lines = generate_diamond(num_lines)
    return render_template('index.html', user_info=current_user, current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'), diamond_lines=diamond_lines)

def generate_diamond(num_lines):
    lines = []
    text = "formulqsolutions"
    text_length = len(text)

    for i in range(1, num_lines ):
        line = ' ' * (num_lines - i)
        for j in range(2 * i - 1):
            line += text[j % text_length]
        lines.append(line)

    for i in range(num_lines , 0, -1):
        line = ' ' * (num_lines - i)
        for j in range(2 * i - 1):
            line += text[j % text_length]
        lines.append(line)

    return lines

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

if __name__ == "__main__":
    app.run(debug=True)