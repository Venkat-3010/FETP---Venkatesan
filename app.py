import json
import os
import sqlite3

os.environ['OAUTH2LIB_INSECURE_TRANSPORT'] = '1'

from flask import Flask,redirect,request,url_for
from flask_login import(
    login_manager,
    current_user,
    login_required,
    login_user,
    logout_user,
    )

from oauthlib.oauth2 import WebApplicationClient
import requests

import db import init_db_command
from user import User

GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', None)
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', None)

GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)

if __name__ == "__main__":
    app.run(debug=True)