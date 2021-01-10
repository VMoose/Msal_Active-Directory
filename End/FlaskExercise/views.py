from flask import render_template, redirect, request, session, url_for
from flask_login import current_user, login_user, logout_user, login_required
import msal
import uuid
import requests
from flask_avatars import Avatars
from config import Config
from FlaskExercise import app
from FlaskExercise.models import User


@app.route('/')
@app.route('/home')
@login_required
def home():
    user = get_data(Config.GRAPH_USER_URL)
    save_image()
    return render_template('index.html'
                           , user=user.json()
                           , image_file=Config.IMAGE_NAME
                           )


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    session['state'] = str(uuid.uuid4())
    auth_url = _build_auth_url(scopes=Config.SCOPE, state=session['state'])
    return render_template('login.html', title='Sign In', auth_url=auth_url)


@app.route('/logout')
def logout():
    logout_user() # Log out of Flask session
    if session.get('user'): # Used MS Login
        # Wipe out user and its token cache from session
        session.clear()
        # Also logout from your tenant's web session
        # And make sure to redirect from there back to the login page
        return redirect(
            Config.AUTHORITY + '/oauth2/v2.0/logout' +
            '?post_logout_redirect_uri=' + url_for('login', _external=True))

    return redirect(url_for('login'))


@app.route(Config.REDIRECT_PATH)  # Its absolute URL must match your app's redirect_uri set in AAD
def authorized():
    if request.args.get('state') != session.get('state'):
        return redirect(url_for('home'))  # Failed, go back home
    if 'error' in request.args:  # Authentication/Authorization failure
        return render_template('auth_error.html', result=request.args)
    if request.args.get('code'):
        cache = _load_cache()
        # Acquire a token by authorization code from an MSAL app
        # And replace the error dictionary
        result = _build_msal_app(cache=cache).acquire_token_by_authorization_code(
            request.args['code'],
            scopes=Config.SCOPE,
            redirect_uri=url_for('authorized', _external=True, _scheme='https'))
        if 'error' in result:
            return render_template('auth_error.html', result=result)
        session['user'] = result.get('id_token_claims')
        # Note: In a real app, use the appropriate user's DB ID below,
        #   but here, we'll just log in with a fake user zero
        #   This is so flask login functionality works appropriately.
        user = User(0)
        login_user(user)
        _save_cache(cache)

    return redirect(url_for('home'))


def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get('token_cache'):
        cache.deserialize(session['token_cache'])
    return cache


def _save_cache(cache):
    if cache.has_state_changed:
        session['token_cache'] = cache.serialize()


def _build_msal_app(cache=None, authority=None):
    # Create and return a Confidential Client Application from msal
    return msal.ConfidentialClientApplication(
        Config.CLIENT_ID, authority=authority or Config.AUTHORITY,
        client_credential=Config.CLIENT_SECRET, token_cache=cache)


def _build_auth_url(authority=None, scopes=None, state=None):
    # Get the authorization request URL from a built msal app, and return it
    return _build_msal_app(authority=authority).get_authorization_request_url(
        scopes or [],
        state=state or str(uuid.uuid4()),
        redirect_uri=url_for('authorized', _external=True, _scheme='https'))


def _get_token_from_cache(scope=None):
    cache = _load_cache()  # This web app maintains one cache per session
    cca = _build_msal_app(cache=cache)
    accounts = cca.get_accounts()
    if accounts:  # So all account(s) belong to the current signed-in user
        result = cca.acquire_token_silent(scope, account=accounts[0])
        _save_cache(cache)
        return result


def get_data(url=None):
    token = _get_token_from_cache(Config.SCOPE)
    data = requests.get(url
                        , headers=dict(Authorization='Bearer {0}'
                                       .format(token['access_token'])))
    return data


def save_image():
    image = get_data(Config.GRAPH_IMAGE_URL)
    if image.ok:
        photo = image.content
    else:
        photo = Avatars.gravatar('email_hash', size=300)
    filename = Config.SAVE_AS
    with open(filename, 'wb') as fhandle:
        fhandle.write(photo)
