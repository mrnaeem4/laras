"""
blueprints/auth.py
Login / logout and the Flask-Login User model.

Routes:
  GET/POST /auth/login   -> login form / handle login
  POST     /auth/logout  -> log the current user out

No self-registration route on purpose — this is an internal SOC tool;
accounts are created via the `flask create-user` CLI command registered
in app.py, by whoever administers the deployment. If you want a signup
page later, add it here explicitly rather than assuming it's wanted.
"""

from __future__ import annotations

from datetime import datetime, timezone

from bson import ObjectId
from bson.errors import InvalidId
from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash

from database import get_users_collection

auth_bp = Blueprint('auth', __name__)
login_manager = LoginManager()
setattr(login_manager, 'login_view', 'auth.login')
login_manager.login_message = 'Silakan login untuk melanjutkan.'
login_manager.login_message_category = 'warning'


class User(UserMixin):
    """Thin wrapper around a `users` MongoDB document for Flask-Login.

    Flask-Login only needs `get_id()` to return a stable string identity
    (used to look the user back up on every request via `user_loader`
    below) — everything else it reads off this object directly.
    """

    def __init__(self, doc: dict):
        self._doc = doc

    def get_id(self) -> str:
        return str(self._doc['_id'])

    @property
    def username(self) -> str:
        return self._doc.get('username', '')

    @property
    def is_active(self) -> bool:  # pyright: ignore[reportIncompatibleMethodOverride]
        return bool(self._doc.get('is_active', True))


@login_manager.user_loader
def load_user(user_id: str):
    """Called by Flask-Login on every request to re-hydrate `current_user`
    from the session's stored user id. Returning None (invalid id, user
    deleted, or DB unavailable) forces the request to be treated as
    anonymous, which is the safe failure mode here."""
    col = get_users_collection()
    if col is None:
        return None
    try:
        doc = col.find_one({'_id': ObjectId(user_id)})
    except InvalidId:
        return None
    if doc is None or not doc.get('is_active', True):
        return None
    return User(doc)


# ── routes ────────────────────────────────────────────────────────────

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('pages.decoder_builder_page'))

    if request.method == 'GET':
        return render_template('login.html')

    col = get_users_collection()
    if col is None:
        flash('MongoDB tidak tersedia. Tidak bisa login.', 'danger')
        return render_template('login.html'), 503

    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''

    doc = col.find_one({'username': username})
    if doc is None or not doc.get('is_active', True) or not check_password_hash(doc.get('password_hash', ''), password):
        # Deliberately identical error for "no such user" and "wrong
        # password" — distinguishing them lets an attacker enumerate
        # valid usernames.
        flash('Username atau password salah.', 'danger')
        return render_template('login.html'), 401

    login_user(User(doc), remember=False)
    col.update_one({'_id': doc['_id']}, {'$set': {'last_login_at': datetime.now(timezone.utc)}})

    # Track this session for instant-revocation purposes — see
    # revoke_user_sessions() for why this is populated independently of
    # Flask-Session's own storage instead of decoding its internal blob.
    from database import get_client
    client = get_client()
    if client is not None:
        session_sid = getattr(session, 'sid', None)
        if session_sid is None:
            return redirect(url_for('pages.decoder_builder_page'))
        from config import Config
        db_name = Config.SESSION_MONGODB_DB or Config.MONGO_DB_NAME
        client[db_name]['session_index'].update_one(
            {'sid': session_sid},
            {'$set': {
                'sid': session_sid,
                'user_id': str(doc['_id']),
                'username': doc.get('username', ''),
                'created_at': datetime.now(timezone.utc),
            }},
            upsert=True,
        )

    next_url = request.args.get('next')
    # Only ever follow a same-site relative path from `next` — an
    # absolute/external URL there would make this an open redirect.
    if not next_url or not next_url.startswith('/'):
        next_url = url_for('pages.decoder_builder_page')
    return redirect(next_url)


@auth_bp.route('/logout', methods=['GET'])
@login_required
def logout():
    from database import get_client
    client = get_client()
    if client is not None:
        session_sid = getattr(session, 'sid', None)
        from config import Config
        db_name = Config.SESSION_MONGODB_DB or Config.MONGO_DB_NAME
        if session_sid is not None:
            client[db_name]['session_index'].delete_one({'sid': session_sid})
    logout_user()
    return redirect(url_for('auth.login'))


@auth_bp.route('/whoami')
@login_required
def whoami():
    """Small JSON endpoint frontend JS can call to know who's logged in
    (e.g. to show a username in the navbar) without a full page render."""
    return jsonify({'username': current_user.username})


# ── revocation helper ────────────────────────────────────────────────

def revoke_user_sessions(username: str) -> int:
    """
    Instantly invalidate every active session belonging to `username` by
    deleting its underlying Flask-Session MongoDB documents. This is the
    entire reason MongoDB-backed server-side sessions were chosen over
    Flask's default signed-cookie session (which can't be revoked before
    it expires without rotating SECRET_KEY and logging out every user at
    once).

    Returns the number of sessions revoked. Safe to call with zero active
    sessions (returns 0). No admin UI is wired to this yet — call it from
    wherever an account-disable/compromise action ends up living.

    Implementation note: Flask-Session's own `sessions` collection stores
    each session as an opaque encoded blob (`val`), not a queryable
    top-level user id — and its serialization format is explicitly
    documented as subject to change, so decoding it here would be fragile
    across Flask-Session versions. Instead, `login()` below independently
    records {sid, user_id} into our own `session_index` collection at
    login time (`flask.session.sid` is a real, documented attribute of
    the active ServerSideSession — see flask_session/base.py). Revoking
    then means: look up this user's tracked sids, delete Flask-Session's
    documents matching `id == "session:" + sid` (key_prefix from
    Flask-Session's own SESSION_KEY_PREFIX default), and drop our index
    entries. `session_index` is fully independent of Flask-Session's
    internal schema, so it keeps working across Flask-Session upgrades.
    """
    from database import get_client
    from config import Config

    client = get_client()
    if client is None:
        return 0

    users_col = get_users_collection()
    if users_col is None:
        return 0
    user_doc = users_col.find_one({'username': username})
    if user_doc is None:
        return 0
    target_id = str(user_doc['_id'])

    db_name = Config.SESSION_MONGODB_DB or Config.MONGO_DB_NAME
    db = client[db_name]
    sessions_col = db[Config.SESSION_MONGODB_COLLECT]
    index_col = db['session_index']

    tracked = list(index_col.find({'user_id': target_id}))
    if not tracked:
        return 0

    key_prefix = 'session:'  # Flask-Session's SESSION_KEY_PREFIX default; we don't override it
    store_ids = [key_prefix + t['sid'] for t in tracked]
    result = sessions_col.delete_many({'id': {'$in': store_ids}})
    index_col.delete_many({'user_id': target_id})
    return result.deleted_count