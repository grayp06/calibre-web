# -*- coding: utf-8 -*-

#  This file is part of the Calibre-Web (https://github.com/janeczku/calibre-web)
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see <http://www.gnu.org/licenses/>.

import time
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlsplit

from flask import Blueprint, request, jsonify, make_response, flash, g
from flask import session as flask_session
from flask_babel import gettext as _
from flask_limiter.util import get_remote_address
from sqlalchemy.exc import IntegrityError, InvalidRequestError, OperationalError
from sqlalchemy.sql.expression import func

from . import config, logger, ub, limiter
from .cw_login import login_user, current_user
from .redirect import get_redirect_location
from .string_helper import strip_whitespaces
from .usermanagement import load_user_from_reverse_proxy_header

try:
    from webauthn import (generate_registration_options, verify_registration_response,
                          generate_authentication_options, verify_authentication_response,
                          options_to_json, base64url_to_bytes)
    from webauthn.helpers import bytes_to_base64url
    from webauthn.helpers.exceptions import WebAuthnException
    from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, AuthenticatorTransport,
                                          PublicKeyCredentialDescriptor, ResidentKeyRequirement,
                                          UserVerificationRequirement)
    webauthn_support = True
    import_error = None
except ImportError as err:
    webauthn_support = False
    import_error = err


passkey = Blueprint('passkey', __name__)
log = logger.create()

if not webauthn_support:
    log.debug("Cannot import webauthn, logging in with passkeys will not work: %s", import_error)

# Challenges are single use and are discarded after this many seconds
CHALLENGE_TIMEOUT = 300
REGISTRATION_CHALLENGE_KEY = "webauthn_registration_challenge"
AUTHENTICATION_CHALLENGE_KEY = "webauthn_authentication_challenge"
NICKNAME_MAX_LENGTH = 64


def passkeys_enabled():
    return bool(webauthn_support and config.config_webauthn_enabled)


def get_rp_id():
    """Relying party id, defaults to the host name the request was made to."""
    if config.config_webauthn_rp_id:
        return config.config_webauthn_rp_id
    return urlsplit(request.host_url).hostname or ""


def get_rp_name():
    return config.config_webauthn_rp_name or config.config_calibre_web_title or "Calibre-Web"


def get_expected_origins():
    """Origins an assertion is accepted from, defaults to the origin the request was made to."""
    if config.config_webauthn_origin:
        return [strip_whitespaces(o) for o in config.config_webauthn_origin.split(",") if strip_whitespaces(o)]
    return [request.host_url.rstrip("/")]


def get_user_verification():
    try:
        return UserVerificationRequirement(config.config_webauthn_user_verification or "preferred")
    except ValueError:
        log.warning("Invalid user verification setting '%s', falling back to 'preferred'",
                    config.config_webauthn_user_verification)
        return UserVerificationRequirement.PREFERRED


def user_verification_required():
    return get_user_verification() == UserVerificationRequirement.REQUIRED


def passkey_login_required(f):
    """Same as user_login_required, but answers with json instead of redirecting to the login page."""
    @wraps(f)
    def inner(*args, **kwargs):
        if config.config_allow_reverse_proxy_header_login:
            g.flask_httpauth_user = load_user_from_reverse_proxy_header(request)
            if g.flask_httpauth_user:
                return f(*args, **kwargs)
        if current_user is not None and current_user.is_authenticated:
            return f(*args, **kwargs)
        return _error(_("Please log in to manage passkeys"), 401)

    return inner


def passkey_feature_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if not passkeys_enabled():
            return _error(_("Passkey authentication is not enabled"), 403)
        return f(*args, **kwargs)

    return inner


def _error(message, status):
    return make_response(jsonify(status="error", message=message), status)


def _json_options(options):
    # options_to_json returns the encoding the browser expects, don't run it through jsonify again
    response = make_response(options_to_json(options))
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    return response


def _store_challenge(key, challenge):
    flask_session[key] = {"challenge": bytes_to_base64url(challenge),
                          "expires": int(time.time()) + CHALLENGE_TIMEOUT}


def _pop_challenge(key):
    """Return the pending challenge, if any. Challenges are always consumed, valid or not."""
    stored = flask_session.pop(key, None)
    if not isinstance(stored, dict) or not stored.get("challenge"):
        return None
    if stored.get("expires", 0) < int(time.time()):
        log.debug("Discarding expired webauthn challenge")
        return None
    try:
        return base64url_to_bytes(stored["challenge"])
    except Exception:
        return None


def _credentials_of(user_id, active_only=True):
    query = ub.session.query(ub.WebAuthnCredential).filter(ub.WebAuthnCredential.user_id == user_id)
    if active_only:
        query = query.filter(ub.WebAuthnCredential.is_active.is_(True))
    return query.order_by(ub.WebAuthnCredential.created).all()


def list_user_passkeys(user_id):
    """Passkeys of a user, for rendering the management section of a profile."""
    if not user_id:
        return []
    try:
        return _credentials_of(user_id, active_only=False)
    except (OperationalError, InvalidRequestError) as ex:
        ub.session.rollback()
        log.error_or_exception("Could not read passkeys: {}".format(ex))
        return []


def _descriptors(credentials):
    descriptors = []
    for credential in credentials:
        try:
            descriptors.append(PublicKeyCredentialDescriptor(id=base64url_to_bytes(credential.credential_id),
                                                             transports=_transports_of(credential)))
        except Exception as ex:
            log.warning("Skipping unreadable webauthn credential %s: %s", credential.id, ex)
    return descriptors


def _transports_of(credential):
    transports = []
    for name in (credential.transports or "").split(","):
        name = strip_whitespaces(name)
        if not name:
            continue
        try:
            transports.append(AuthenticatorTransport(name))
        except ValueError:
            log.debug("Ignoring unknown authenticator transport '%s'", name)
    return transports or None


def _normalize_credential_id(value):
    """Clients may or may not pad their base64url, the database holds the unpadded form."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return bytes_to_base64url(base64url_to_bytes(value))
    except Exception:
        return None


def _log_failure(message, *args):
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    log.warning(message + ' IP-address: %s', *(args + (ip_address,)))


@passkey.route("/webauthn/register/options", methods=["POST"])
@passkey_login_required
@passkey_feature_required
def register_options():
    options = generate_registration_options(
        rp_id=get_rp_id(),
        rp_name=get_rp_name(),
        user_id=str(current_user.id).encode("utf-8"),
        user_name=current_user.name,
        user_display_name=current_user.name,
        timeout=CHALLENGE_TIMEOUT * 1000,
        exclude_credentials=_descriptors(_credentials_of(current_user.id, active_only=False)),
        authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.PREFERRED,
                                                               user_verification=get_user_verification()),
    )
    _store_challenge(REGISTRATION_CHALLENGE_KEY, options.challenge)
    return _json_options(options)


@passkey.route("/webauthn/register/verify", methods=["POST"])
@passkey_login_required
@passkey_feature_required
def register_verify():
    data = request.get_json(silent=True) or {}
    credential = data.get("credential")
    if not credential:
        return _error(_("Invalid passkey registration"), 400)

    challenge = _pop_challenge(REGISTRATION_CHALLENGE_KEY)
    if not challenge:
        return _error(_("Passkey registration timed out, please try again"), 400)

    try:
        verification = verify_registration_response(credential=credential,
                                                    expected_challenge=challenge,
                                                    expected_rp_id=get_rp_id(),
                                                    expected_origin=get_expected_origins(),
                                                    require_user_verification=user_verification_required())
    except (WebAuthnException, ValueError, KeyError, TypeError) as ex:
        _log_failure('Passkey registration failed for user "%s": %s', current_user.name, ex)
        return _error(_("Invalid passkey registration"), 400)

    credential_id = bytes_to_base64url(verification.credential_id)
    if ub.session.query(ub.WebAuthnCredential).filter(
            ub.WebAuthnCredential.credential_id == credential_id).first():
        return _error(_("This passkey is already registered"), 409)

    nickname = strip_whitespaces(str(data.get("nickname", "")))[:NICKNAME_MAX_LENGTH]
    stored = ub.WebAuthnCredential()
    stored.user_id = current_user.id
    stored.credential_id = credential_id
    stored.public_key = bytes_to_base64url(verification.credential_public_key)
    stored.sign_count = verification.sign_count or 0
    stored.aaguid = verification.aaguid or ""
    stored.transports = ",".join(_requested_transports(credential))
    stored.nickname = nickname or _("Passkey")
    stored.is_active = True

    try:
        ub.session.add(stored)
        ub.session.commit()
    except (IntegrityError, OperationalError, InvalidRequestError) as ex:
        ub.session.rollback()
        log.error_or_exception("Could not store passkey: {}".format(ex))
        return _error(_("Oops! An unknown error occurred. Please try again later."), 500)

    log.info("Passkey '%s' registered for user '%s'", stored.nickname, current_user.name)
    return jsonify(status="success", credential={"id": stored.id, "nickname": stored.nickname})


def _requested_transports(credential):
    """Transports the browser reported for the new credential, filtered to the known ones."""
    try:
        reported = credential.get("response", {}).get("transports") or []
    except AttributeError:
        return []
    transports = []
    for name in reported:
        try:
            transports.append(AuthenticatorTransport(name).value)
        except ValueError:
            log.debug("Ignoring unknown authenticator transport '%s'", name)
    return transports


@passkey.route("/webauthn/credentials/<int:credential_id>/delete", methods=["POST"])
@passkey_login_required
def delete_credential(credential_id):
    # deliberately not gated on the feature switch, a passkey stays revocable after passkeys are turned off
    credential = ub.session.query(ub.WebAuthnCredential).filter(
        ub.WebAuthnCredential.id == credential_id).first()
    if not credential:
        return _error(_("Passkey not found"), 404)
    if credential.user_id != current_user.id and not current_user.role_admin():
        log.warning("User '%s' tried to delete a passkey of another user", current_user.name)
        return _error(_("Passkey not found"), 404)

    try:
        ub.session.delete(credential)
        ub.session.commit()
    except (OperationalError, InvalidRequestError) as ex:
        ub.session.rollback()
        log.error_or_exception("Could not delete passkey: {}".format(ex))
        return _error(_("Oops! An unknown error occurred. Please try again later."), 500)

    log.info("Passkey '%s' deleted by user '%s'", credential.nickname, current_user.name)
    return jsonify(status="success")


@passkey.route("/webauthn/auth/options", methods=["POST"])
@passkey_feature_required
@limiter.limit("300/day", key_func=get_remote_address)
@limiter.limit("20/minute", key_func=get_remote_address)
def authenticate_options():
    data = request.get_json(silent=True) or {}
    username = strip_whitespaces(str(data.get("username", "")))
    allow_credentials = []
    if username:
        user = ub.session.query(ub.User).filter(func.lower(ub.User.name) == username.lower()).first()
        # an unknown user still gets options back, so the response can't be used to enumerate accounts
        if user and not user.role_anonymous():
            allow_credentials = _descriptors(_credentials_of(user.id))

    options = generate_authentication_options(rp_id=get_rp_id(),
                                              timeout=CHALLENGE_TIMEOUT * 1000,
                                              allow_credentials=allow_credentials,
                                              user_verification=get_user_verification())
    _store_challenge(AUTHENTICATION_CHALLENGE_KEY, options.challenge)
    return _json_options(options)


@passkey.route("/webauthn/auth/verify", methods=["POST"])
@passkey_feature_required
@limiter.limit("300/day", key_func=get_remote_address)
@limiter.limit("10/minute", key_func=get_remote_address)
def authenticate_verify():
    if current_user is not None and current_user.is_authenticated:
        return jsonify(status="success", redirect_url=get_redirect_location(None, "web.index"))

    data = request.get_json(silent=True) or {}
    credential = data.get("credential")
    if not credential:
        return _error(_("Invalid passkey"), 400)

    challenge = _pop_challenge(AUTHENTICATION_CHALLENGE_KEY)
    if not challenge:
        return _error(_("Login timed out, please try again"), 400)

    credential_id = _normalize_credential_id(credential.get("rawId") or credential.get("id"))
    stored = None
    if credential_id:
        stored = ub.session.query(ub.WebAuthnCredential).filter(
            ub.WebAuthnCredential.credential_id == credential_id,
            ub.WebAuthnCredential.is_active.is_(True)).first()
    if not stored:
        _log_failure('Passkey login failed, unknown credential.')
        return _error(_("Wrong Username or Password"), 401)

    user = ub.session.query(ub.User).filter(ub.User.id == stored.user_id).first()
    if not user or user.role_anonymous():
        _log_failure('Passkey login failed, credential %s has no usable user.', stored.id)
        return _error(_("Wrong Username or Password"), 401)

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=get_rp_id(),
            expected_origin=get_expected_origins(),
            credential_public_key=base64url_to_bytes(stored.public_key),
            credential_current_sign_count=stored.sign_count or 0,
            require_user_verification=user_verification_required())
    except (WebAuthnException, ValueError, KeyError, TypeError) as ex:
        _log_failure('Passkey login failed for user "%s": %s', user.name, ex)
        return _error(_("Wrong Username or Password"), 401)

    stored.sign_count = verification.new_sign_count
    stored.last_used = datetime.now(timezone.utc)
    ub.session_commit()

    login_user(user, remember=bool(data.get("remember_me", True)))
    [limiter.limiter.clear(limit.limit, *limit.request_args) for limit in limiter.current_limits]
    log.debug("User '%s' logged in with passkey '%s'", user.name, stored.nickname)
    flash(_("You are now logged in as: '%(nickname)s'", nickname=user.name), category="success")

    return jsonify(status="success",
                   redirect_url=get_redirect_location(data.get("next", None), "web.index"))
