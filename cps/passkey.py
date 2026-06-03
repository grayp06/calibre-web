# -*- coding: utf-8 -*-
import json

from flask import Blueprint, request, session, jsonify, abort
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    PublicKeyCredentialDescriptor,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

from . import ub, logger, csrf
from .cw_login import login_user, current_user

passkey_bp = Blueprint('passkey', __name__)
log = logger.create()

if csrf:
    csrf.exempt(passkey_bp)


def _rp_id():
    return request.host.split(':')[0]


def _origin():
    return request.scheme + '://' + request.host


@passkey_bp.route('/passkey/register/begin', methods=['POST'])
def register_begin():
    if not current_user.is_authenticated:
        abort(401)
    existing = ub.session.query(ub.Passkey).filter_by(user_id=current_user.id).all()
    exclude = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(p.credential_id))
        for p in existing
    ]
    options = generate_registration_options(
        rp_id=_rp_id(),
        rp_name="Calibre-Web",
        user_id=str(current_user.id).encode(),
        user_name=current_user.name,
        user_display_name=current_user.name,
        exclude_credentials=exclude,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    session['passkey_reg_challenge'] = bytes_to_base64url(options.challenge)
    return options_to_json(options), 200, {'Content-Type': 'application/json'}


@passkey_bp.route('/passkey/register/complete', methods=['POST'])
def register_complete():
    if not current_user.is_authenticated:
        abort(401)
    stored_challenge = session.pop('passkey_reg_challenge', None)
    if not stored_challenge:
        return jsonify({"error": "No active registration challenge"}), 400
    raw_body = request.get_data()
    try:
        verification = verify_registration_response(
            credential=raw_body,
            expected_challenge=base64url_to_bytes(stored_challenge),
            expected_rp_id=_rp_id(),
            expected_origin=_origin(),
        )
    except Exception as e:
        log.error("Passkey registration failed: %s", e)
        return jsonify({"error": str(e)}), 400

    name = request.args.get('name', 'Passkey')
    new_pk = ub.Passkey(
        user_id=current_user.id,
        credential_id=bytes_to_base64url(verification.credential_id),
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        name=name,
    )
    ub.session.add(new_pk)
    try:
        ub.session.commit()
    except Exception as e:
        ub.session.rollback()
        log.error("Database error saving passkey: %s", e)
        return jsonify({"error": "Database error"}), 500
    return jsonify({"verified": True, "id": new_pk.id, "name": new_pk.name})


@passkey_bp.route('/passkey/login/begin', methods=['POST'])
def login_begin():
    options = generate_authentication_options(
        rp_id=_rp_id(),
        allow_credentials=[],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    session['passkey_auth_challenge'] = bytes_to_base64url(options.challenge)
    return options_to_json(options), 200, {'Content-Type': 'application/json'}


@passkey_bp.route('/passkey/login/complete', methods=['POST'])
def login_complete():
    stored_challenge = session.pop('passkey_auth_challenge', None)
    if not stored_challenge:
        return jsonify({"error": "No active authentication challenge"}), 400
    raw_body = request.get_data()
    try:
        data = json.loads(raw_body)
        credential_id = data.get('id', '')
    except Exception:
        return jsonify({"error": "Invalid request body"}), 400

    stored = ub.session.query(ub.Passkey).filter_by(credential_id=credential_id).first()
    if not stored:
        return jsonify({"error": "Unknown passkey"}), 404

    try:
        verification = verify_authentication_response(
            credential=raw_body,
            expected_challenge=base64url_to_bytes(stored_challenge),
            expected_rp_id=_rp_id(),
            expected_origin=_origin(),
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
        )
    except Exception as e:
        log.error("Passkey authentication failed: %s", e)
        return jsonify({"error": str(e)}), 400

    stored.sign_count = verification.new_sign_count
    try:
        ub.session.commit()
    except Exception:
        ub.session.rollback()

    user = ub.session.query(ub.User).filter_by(id=stored.user_id).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    login_user(user)
    next_url = request.args.get('next', '/')
    return jsonify({"verified": True, "redirect": next_url})


@passkey_bp.route('/passkey/delete/<int:pk_id>', methods=['POST'])
def delete_passkey(pk_id):
    if not current_user.is_authenticated:
        abort(401)
    stored = ub.session.query(ub.Passkey).filter_by(id=pk_id, user_id=current_user.id).first()
    if not stored:
        abort(404)
    ub.session.delete(stored)
    try:
        ub.session.commit()
    except Exception as e:
        ub.session.rollback()
        log.error("Database error deleting passkey: %s", e)
        return jsonify({"error": "Database error"}), 500
    return jsonify({"deleted": True})
