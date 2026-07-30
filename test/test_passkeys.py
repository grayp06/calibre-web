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

"""End to end tests for the passkey (WebAuthn/FIDO2) login.

The browser side is replaced by a software authenticator that produces real
ES256 signatures, so the responses are verified by the same code path a real
authenticator would go through.
"""

import base64
import hashlib
import json
import os
import struct
import sys
import time

import pytest

pytest.importorskip("webauthn")

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RP_ID = "example.org"
ORIGIN = "https://example.org"
AAGUID = b"\x00" * 16


def b64url(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def from_b64url(data):
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class SoftwareAuthenticator:
    """Minimal FIDO2 authenticator, enough to exercise registration and assertion."""

    def __init__(self, credential_id=None):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = credential_id or os.urandom(32)
        self.sign_count = 0

    def _cose_key(self):
        numbers = self.private_key.public_key().public_numbers()
        return cbor2.dumps({1: 2,
                            3: -7,
                            -1: 1,
                            -2: numbers.x.to_bytes(32, "big"),
                            -3: numbers.y.to_bytes(32, "big")})

    def _authenticator_data(self, rp_id, flags, attested=False):
        data = hashlib.sha256(rp_id.encode()).digest()
        data += struct.pack(">B", flags)
        data += struct.pack(">I", self.sign_count)
        if attested:
            data += AAGUID
            data += struct.pack(">H", len(self.credential_id))
            data += self.credential_id
            data += self._cose_key()
        return data

    @staticmethod
    def _client_data(client_type, challenge, origin):
        return json.dumps({"type": client_type,
                           "challenge": challenge,
                           "origin": origin,
                           "crossOrigin": False}).encode()

    def register(self, options, origin=ORIGIN, rp_id=None):
        rp_id = rp_id or options["rp"]["id"]
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        # user present + user verified + attested credential data
        auth_data = self._authenticator_data(rp_id, 0x45, attested=True)
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {"id": b64url(self.credential_id),
                "rawId": b64url(self.credential_id),
                "type": "public-key",
                "clientExtensionResults": {},
                "response": {"clientDataJSON": b64url(client_data),
                             "attestationObject": b64url(attestation),
                             "transports": ["internal"]}}

    def authenticate(self, options, origin=ORIGIN, rp_id=None, sign_count=None):
        rp_id = rp_id or options["rpId"]
        if sign_count is not None:
            self.sign_count = sign_count
        else:
            self.sign_count += 1
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        # user present + user verified
        auth_data = self._authenticator_data(rp_id, 0x05)
        signature = self.private_key.sign(auth_data + hashlib.sha256(client_data).digest(),
                                          ec.ECDSA(hashes.SHA256()))
        return {"id": b64url(self.credential_id),
                "rawId": b64url(self.credential_id),
                "type": "public-key",
                "clientExtensionResults": {},
                "response": {"clientDataJSON": b64url(client_data),
                             "authenticatorData": b64url(auth_data),
                             "signature": b64url(signature),
                             "userHandle": None}}


@pytest.fixture(scope="module")
def application(tmp_path_factory):
    settings_dir = tmp_path_factory.mktemp("calibre-web")
    db_path = str(settings_dir / "app.db")
    sys.argv = ["cps", "-p", db_path, "-g", str(settings_dir / "gdrive.db")]

    from flask import Blueprint
    from cps import app, cli_param, config, config_sql, lm, limiter, ub
    from cps.cw_login import login_user, logout_user
    from cps.passkeys import passkey
    from cps.reverseproxy import ReverseProxied

    cli_param.init()
    ub.init_db(db_path)
    encrypt_key, __ = config_sql.get_encryption_key(str(settings_dir))
    config_sql.load_configuration(ub.session, encrypt_key)
    config.init_config(ub.session, encrypt_key, cli_param)

    config.config_webauthn_enabled = True
    config.config_webauthn_rp_id = RP_ID
    config.config_webauthn_rp_name = "Calibre-Web Test"
    config.config_webauthn_origin = ORIGIN
    config.config_webauthn_user_verification = "preferred"

    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, RATELIMIT_ENABLED=False)
    app.secret_key = "passkey-test-secret"
    # the login manager reads the script name off the middleware when it sets the remember cookie
    app.wsgi_app = ReverseProxied(app.wsgi_app)
    lm.login_view = "web.login"
    lm.anonymous_user = ub.Anonymous
    lm.session_protection = "basic"
    lm.init_app(app)
    limiter.init_app(app)

    from cps.cw_babel import babel, get_locale
    babel.init_app(app, locale_selector=get_locale)

    # stand-ins for the routes the passkey blueprint redirects to
    web = Blueprint("web", __name__)

    @web.route("/")
    def index():
        return "index"

    @web.route("/login")
    def login():
        return "login"

    @web.route("/testlogin/<int:user_id>", methods=["POST"])
    def testlogin(user_id):
        login_user(ub.session.query(ub.User).filter(ub.User.id == user_id).first())
        return "ok"

    @web.route("/testlogout", methods=["POST"])
    def testlogout():
        logout_user()
        return "ok"

    app.register_blueprint(web)
    app.register_blueprint(passkey)
    return app


@pytest.fixture
def env(application):
    from werkzeug.security import generate_password_hash
    from cps import constants, ub

    ub.session.query(ub.WebAuthnCredential).delete()
    ub.session.query(ub.User_Sessions).delete()
    ub.session.query(ub.User).filter(ub.User.name.in_(["alice", "bob"])).delete(synchronize_session=False)
    ub.session.commit()
    ub.session.expire_all()

    users = {}
    for name in ("alice", "bob"):
        user = ub.User()
        user.name = name
        user.email = name + "@example.org"
        user.role = constants.ROLE_USER
        user.password = generate_password_hash("secret")
        ub.session.add(user)
        users[name] = user
    ub.session.commit()

    client = application.test_client()
    client.environ_base["HTTP_HOST"] = RP_ID
    return {"client": client, "users": users, "ub": ub}


def login_as(env, name):
    response = env["client"].post("/testlogin/{}".format(env["users"][name].id))
    assert response.status_code == 200


def logout(env):
    assert env["client"].post("/testlogout").status_code == 200


def register_passkey(env, authenticator, nickname="Test key"):
    client = env["client"]
    options = client.post("/webauthn/register/options", json={}).get_json()
    credential = authenticator.register(options)
    return client.post("/webauthn/register/verify",
                       json={"credential": credential, "nickname": nickname})


def register_and_logout(env):
    """Register a passkey for alice, then start from a logged out session."""
    login_as(env, "alice")
    authenticator = SoftwareAuthenticator()
    assert register_passkey(env, authenticator).status_code == 200
    logout(env)
    return authenticator


def authentication_options(env, username=""):
    return env["client"].post("/webauthn/auth/options", json={"username": username}).get_json()


# ############################### registration ################################

def test_registration_requires_login(env):
    assert env["client"].post("/webauthn/register/options", json={}).status_code == 401


def test_registration_round_trip(env):
    login_as(env, "alice")
    response = register_passkey(env, SoftwareAuthenticator(), nickname="Yubikey")
    assert response.status_code == 200
    assert response.get_json()["status"] == "success"

    stored = env["ub"].session.query(env["ub"].WebAuthnCredential).all()
    assert len(stored) == 1
    assert stored[0].user_id == env["users"]["alice"].id
    assert stored[0].nickname == "Yubikey"
    assert stored[0].transports == "internal"
    assert stored[0].is_active is True


def test_registration_options_exclude_known_credentials(env):
    login_as(env, "alice")
    authenticator = SoftwareAuthenticator()
    register_passkey(env, authenticator)

    options = env["client"].post("/webauthn/register/options", json={}).get_json()
    excluded = [from_b64url(c["id"]) for c in options["excludeCredentials"]]
    assert authenticator.credential_id in excluded


def test_registration_rejects_wrong_origin(env):
    login_as(env, "alice")
    client = env["client"]
    options = client.post("/webauthn/register/options", json={}).get_json()
    credential = SoftwareAuthenticator().register(options, origin="https://evil.example.net")

    response = client.post("/webauthn/register/verify", json={"credential": credential})
    assert response.status_code == 400
    assert env["ub"].session.query(env["ub"].WebAuthnCredential).count() == 0


def test_registration_challenge_is_single_use(env):
    login_as(env, "alice")
    client = env["client"]
    options = client.post("/webauthn/register/options", json={}).get_json()
    credential = SoftwareAuthenticator().register(options)

    assert client.post("/webauthn/register/verify", json={"credential": credential}).status_code == 200
    replay = client.post("/webauthn/register/verify", json={"credential": credential})
    assert replay.status_code == 400


def test_registration_rejects_expired_challenge(env):
    from cps.passkeys import REGISTRATION_CHALLENGE_KEY

    login_as(env, "alice")
    client = env["client"]
    options = client.post("/webauthn/register/options", json={}).get_json()
    credential = SoftwareAuthenticator().register(options)

    with client.session_transaction() as session:
        pending = session[REGISTRATION_CHALLENGE_KEY]
        pending["expires"] = int(time.time()) - 1
        session[REGISTRATION_CHALLENGE_KEY] = pending

    response = client.post("/webauthn/register/verify", json={"credential": credential})
    assert response.status_code == 400
    assert env["ub"].session.query(env["ub"].WebAuthnCredential).count() == 0


def test_registration_rejects_credential_of_other_user(env):
    login_as(env, "alice")
    authenticator = SoftwareAuthenticator()
    assert register_passkey(env, authenticator).status_code == 200

    env["client"].get("/")
    login_as(env, "bob")
    assert register_passkey(env, authenticator).status_code == 409


# ############################## authentication ###############################

def test_authentication_round_trip(env):
    authenticator = register_and_logout(env)

    client = env["client"]
    options = authentication_options(env)
    credential = authenticator.authenticate(options)
    response = client.post("/webauthn/auth/verify", json={"credential": credential})

    assert response.status_code == 200
    assert response.get_json()["redirect_url"] == "/"
    stored = env["ub"].session.query(env["ub"].WebAuthnCredential).first()
    assert stored.sign_count == authenticator.sign_count
    assert stored.last_used is not None


def test_authentication_options_restrict_to_username(env):
    authenticator = register_and_logout(env)

    allowed = authentication_options(env, "alice")["allowCredentials"]
    assert [from_b64url(c["id"]) for c in allowed] == [authenticator.credential_id]
    # a user without passkeys, and an unknown user, both get a discoverable-credential challenge
    assert authentication_options(env, "bob")["allowCredentials"] == []
    assert authentication_options(env, "nobody")["allowCredentials"] == []


def test_credential_id_lookup_is_padding_insensitive():
    from cps.passkeys import _normalize_credential_id

    raw = os.urandom(32)
    unpadded = b64url(raw)
    padded = unpadded + "=" * (-len(unpadded) % 4)

    assert padded != unpadded
    assert _normalize_credential_id(padded) == unpadded
    assert _normalize_credential_id(unpadded) == unpadded
    assert _normalize_credential_id("") is None
    assert _normalize_credential_id(None) is None


def test_authentication_rejects_unknown_credential(env):
    authenticator = SoftwareAuthenticator()
    options = authentication_options(env)
    credential = authenticator.authenticate(options)

    response = env["client"].post("/webauthn/auth/verify", json={"credential": credential})
    assert response.status_code == 401


def test_authentication_rejects_wrong_origin(env):
    authenticator = register_and_logout(env)

    options = authentication_options(env)
    credential = authenticator.authenticate(options, origin="https://evil.example.net")
    response = env["client"].post("/webauthn/auth/verify", json={"credential": credential})
    assert response.status_code == 401


def test_authentication_rejects_wrong_rp_id(env):
    authenticator = register_and_logout(env)

    options = authentication_options(env)
    credential = authenticator.authenticate(options, rp_id="evil.example.net")
    response = env["client"].post("/webauthn/auth/verify", json={"credential": credential})
    assert response.status_code == 401


def test_authentication_challenge_is_consumed_by_a_failed_attempt(env):
    authenticator = register_and_logout(env)

    client = env["client"]
    options = authentication_options(env)
    rejected = authenticator.authenticate(options, origin="https://evil.example.net")
    assert client.post("/webauthn/auth/verify", json={"credential": rejected}).status_code == 401

    # the challenge is gone now, even a well formed assertion for it is not accepted anymore
    replay = authenticator.authenticate(options)
    assert client.post("/webauthn/auth/verify", json={"credential": replay}).status_code == 400


def test_authentication_rejects_replayed_assertion(env):
    authenticator = register_and_logout(env)

    client = env["client"]
    options = authentication_options(env)
    credential = authenticator.authenticate(options)
    assert client.post("/webauthn/auth/verify", json={"credential": credential}).status_code == 200

    logout(env)
    # a second use of the same assertion has no pending challenge left to match
    assert client.post("/webauthn/auth/verify", json={"credential": credential}).status_code == 400


def test_already_authenticated_session_is_answered_without_a_credential(env):
    login_as(env, "alice")
    response = env["client"].post("/webauthn/auth/verify", json={})
    assert response.status_code == 200
    assert response.get_json()["redirect_url"] == "/"


def test_authentication_rejects_sign_count_rollback(env):
    authenticator = register_and_logout(env)

    client = env["client"]
    options = authentication_options(env)
    assert client.post("/webauthn/auth/verify",
                       json={"credential": authenticator.authenticate(options, sign_count=9)}).status_code == 200

    logout(env)
    options = authentication_options(env)
    cloned = authenticator.authenticate(options, sign_count=4)
    response = client.post("/webauthn/auth/verify", json={"credential": cloned})
    assert response.status_code == 401
    assert env["ub"].session.query(env["ub"].WebAuthnCredential).first().sign_count == 9


def test_authentication_rejects_deactivated_credential(env):
    authenticator = register_and_logout(env)

    stored = env["ub"].session.query(env["ub"].WebAuthnCredential).first()
    stored.is_active = False
    env["ub"].session.commit()

    options = authentication_options(env)
    credential = authenticator.authenticate(options)
    assert env["client"].post("/webauthn/auth/verify", json={"credential": credential}).status_code == 401


# ################################ management #################################

def test_delete_own_passkey(env):
    login_as(env, "alice")
    register_passkey(env, SoftwareAuthenticator())
    stored = env["ub"].session.query(env["ub"].WebAuthnCredential).first()

    response = env["client"].post("/webauthn/credentials/{}/delete".format(stored.id))
    assert response.status_code == 200
    assert env["ub"].session.query(env["ub"].WebAuthnCredential).count() == 0


def test_passkey_can_be_revoked_while_the_feature_is_disabled(env):
    from cps import config

    login_as(env, "alice")
    register_passkey(env, SoftwareAuthenticator())
    stored = env["ub"].session.query(env["ub"].WebAuthnCredential).first()

    config.config_webauthn_enabled = False
    try:
        response = env["client"].post("/webauthn/credentials/{}/delete".format(stored.id))
        assert response.status_code == 200
        assert env["ub"].session.query(env["ub"].WebAuthnCredential).count() == 0
    finally:
        config.config_webauthn_enabled = True


def test_cannot_delete_passkey_of_other_user(env):
    login_as(env, "alice")
    register_passkey(env, SoftwareAuthenticator())
    stored = env["ub"].session.query(env["ub"].WebAuthnCredential).first()

    login_as(env, "bob")
    response = env["client"].post("/webauthn/credentials/{}/delete".format(stored.id))
    assert response.status_code == 404
    assert env["ub"].session.query(env["ub"].WebAuthnCredential).count() == 1


# ################################ migration ##################################

def test_migration_adds_the_credential_table(tmp_path):
    from sqlalchemy import create_engine, inspect, text
    from cps import ub

    engine = create_engine("sqlite:///{}".format(tmp_path / "old.db"))
    ub.Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE webauthn_credential"))
    assert "webauthn_credential" not in inspect(engine).get_table_names()

    ub.add_missing_tables(engine, None)
    assert "webauthn_credential" in inspect(engine).get_table_names()


# ############################## feature switch ###############################

def test_registration_requires_a_discoverable_credential(env):
    login_as(env, "alice")
    options = env["client"].post("/webauthn/register/options", json={}).get_json()

    selection = options["authenticatorSelection"]
    assert selection["residentKey"] == "required"
    # the deprecated companion flag has to agree, older authenticators only look at that one
    assert selection["requireResidentKey"] is True


def test_endpoints_are_off_when_the_relying_party_is_not_configured(env):
    from cps import config

    login_as(env, "alice")
    for field in ("config_webauthn_rp_id", "config_webauthn_origin"):
        original = getattr(config, field)
        setattr(config, field, "")
        try:
            assert env["client"].post("/webauthn/register/options", json={}).status_code == 403
            assert env["client"].post("/webauthn/auth/options", json={}).status_code == 403
            assert env["client"].post("/webauthn/auth/verify", json={}).status_code == 403
        finally:
            setattr(config, field, original)


def test_endpoints_are_off_when_feature_is_disabled(env):
    from cps import config

    login_as(env, "alice")
    config.config_webauthn_enabled = False
    try:
        assert env["client"].post("/webauthn/register/options", json={}).status_code == 403
        assert env["client"].post("/webauthn/auth/options", json={}).status_code == 403
        assert env["client"].post("/webauthn/auth/verify", json={}).status_code == 403
    finally:
        config.config_webauthn_enabled = True
