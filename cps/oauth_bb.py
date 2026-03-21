# -*- coding: utf-8 -*-

#  This file is part of the Calibre-Web (https://github.com/janeczku/calibre-web)
#    Copyright (C) 2018-2019 OzzieIsaacs, cervinko, jkrehm, bodybybuddha, ok11,
#                            andy29485, idalin, Kyosfonica, wuqi, Kennyl, lemmsh,
#                            falgh1, grunjol, csitko, ytils, xybydy, trasba, vrabe,
#                            ruben-herold, marblepebble, JackED42, SiphonSquirrel,
#                            apetresc, nanu-c, mutschler
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
#  along with this program. If not, see <http://www.gnu.org/licenses/>

import json
from functools import wraps

from flask import session, request, make_response, abort
from flask import Blueprint, flash, redirect, url_for
from flask_babel import gettext as _
from flask_dance.consumer import oauth_authorized, oauth_error
from flask_dance.consumer import OAuth2ConsumerBlueprint
from oauthlib.oauth2 import TokenExpiredError, InvalidGrantError
from .cw_login import login_user, current_user
from sqlalchemy.orm.exc import NoResultFound
from .usermanagement import user_login_required

from . import constants, logger, config, app, ub

try:
    from .oauth import OAuthBackend, backend_resultcode
except NameError:
    pass


oauth_check = {}
oauthblueprints = []
oauth = Blueprint('oauth', __name__)
log = logger.create()


def oauth_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if config.config_login_type == constants.LOGIN_OAUTH:
            return f(*args, **kwargs)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            data = {'status': 'error', 'message': 'Not Found'}
            response = make_response(json.dumps(data, ensure_ascii=False))
            response.headers["Content-Type"] = "application/json; charset=utf-8"
            return response, 404
        abort(404)

    return inner


def register_oauth_blueprint(cid, show_name):
    oauth_check[cid] = show_name


def register_user_with_oauth(user=None):
    all_oauth = {}
    for oauth_key in oauth_check.keys():
        if str(oauth_key) + '_oauth_user_id' in session and session[str(oauth_key) + '_oauth_user_id'] != '':
            all_oauth[oauth_key] = oauth_check[oauth_key]
    if len(all_oauth.keys()) == 0:
        return
    if user is None:
        flash(_("Register with %(provider)s", provider=", ".join(list(all_oauth.values()))), category="success")
    else:
        for oauth_key in all_oauth.keys():
            # Find this OAuth token in the database, or create it
            query = ub.session.query(ub.OAuth).filter_by(
                provider=oauth_key,
                provider_user_id=session[str(oauth_key) + "_oauth_user_id"],
            )
            try:
                oauth_key = query.one()
                oauth_key.user_id = user.id
            except NoResultFound:
                # no found, return error
                return
            ub.session_commit("User {} with OAuth for provider {} registered".format(user.name, oauth_key))


def logout_oauth_user():
    for oauth_key in oauth_check.keys():
        if str(oauth_key) + '_oauth_user_id' in session:
            session.pop(str(oauth_key) + '_oauth_user_id')


def oauth_update_token(provider_id, token, provider_user_id):
    session[provider_id + "_oauth_user_id"] = provider_user_id
    session[provider_id + "_oauth_token"] = token

    # Find this OAuth token in the database, or create it
    query = ub.session.query(ub.OAuth).filter_by(
        provider=provider_id,
        provider_user_id=provider_user_id,
    )
    try:
        oauth_entry = query.one()
        # update token
        oauth_entry.token = token
    except NoResultFound:
        oauth_entry = ub.OAuth(
            provider=provider_id,
            provider_user_id=provider_user_id,
            token=token,
        )
    ub.session.add(oauth_entry)
    ub.session_commit()

    # Disable Flask-Dance's default behavior for saving the OAuth token
    # Value differrs depending on flask-dance version
    return backend_resultcode


def bind_oauth_or_register(provider_id, provider_user_id, redirect_url, provider_name):
    query = ub.session.query(ub.OAuth).filter_by(
        provider=provider_id,
        provider_user_id=provider_user_id,
    )
    try:
        oauth_entry = query.first()
        # already bind with user, just login
        if oauth_entry.user:
            login_user(oauth_entry.user)
            log.debug("You are now logged in as: '%s'", oauth_entry.user.name)
            flash(_("Success! You are now logged in as: %(nickname)s", nickname=oauth_entry.user.name),
                  category="success")
            return redirect(url_for('web.index'))
        else:
            # bind to current user
            if current_user and current_user.is_authenticated:
                oauth_entry.user = current_user
                try:
                    ub.session.add(oauth_entry)
                    ub.session.commit()
                    flash(_("Link to %(oauth)s Succeeded", oauth=provider_name), category="success")
                    log.info("Link to {} Succeeded".format(provider_name))
                    return redirect(url_for('web.profile'))
                except Exception as ex:
                    log.error_or_exception(ex)
                    ub.session.rollback()
            else:
                flash(_("Login failed, No User Linked With OAuth Account"), category="error")
            log.info('Login failed, No User Linked With OAuth Account')
            return redirect(url_for('web.login'))
            # return redirect(url_for('web.login'))
            # if config.config_public_reg:
            #   return redirect(url_for('web.register'))
            # else:
            #    flash(_("Public registration is not enabled"), category="error")
            #    return redirect(url_for(redirect_url))
    except (NoResultFound, AttributeError):
        return redirect(url_for(redirect_url))


def get_oauth_status():
    status = []
    query = ub.session.query(ub.OAuth).filter_by(
        user_id=current_user.id,
    )
    try:
        oauths = query.all()
        for oauth_entry in oauths:
            status.append(int(oauth_entry.provider))
        return status
    except NoResultFound:
        return None


def unlink_oauth(provider):
    if request.host_url + 'me' != request.referrer:
        pass
    query = ub.session.query(ub.OAuth).filter_by(
        provider=provider,
        user_id=current_user.id,
    )
    try:
        oauth_entry = query.one()
        if current_user and current_user.is_authenticated:
            oauth_entry.user = current_user
            try:
                ub.session.delete(oauth_entry)
                ub.session.commit()
                logout_oauth_user()
                flash(_("Unlink to %(oauth)s Succeeded", oauth=oauth_check[provider]), category="success")
                log.info("Unlink to {} Succeeded".format(oauth_check[provider]))
            except Exception as ex:
                log.error_or_exception(ex)
                ub.session.rollback()
                flash(_("Unlink to %(oauth)s Failed", oauth=oauth_check[provider]), category="error")
    except NoResultFound:
        log.warning("oauth %s for user %d not found", provider, current_user.id)
        flash(_("Not Linked to %(oauth)s", oauth=provider), category="error")
    return redirect(url_for('web.profile'))


def generate_oauth_blueprints():
    oauth_providers = ub.session.query(ub.OAuthProvider).all()

    for provider_row in oauth_providers:
        scopes = provider_row.scopes.split() if provider_row.scopes else None
        element = dict(
            provider_name=provider_row.provider_name,
            id=provider_row.id,
            active=provider_row.active,
            oauth_client_id=provider_row.oauth_client_id,
            oauth_client_secret=provider_row.oauth_client_secret,
            authorization_url=provider_row.authorization_url,
            token_url=provider_row.token_url,
            api_base_url=provider_row.api_base_url,
            user_info_endpoint=provider_row.user_info_endpoint,
            user_id_field=provider_row.user_id_field or "id",
            scopes=provider_row.scopes or "",
        )
        oauthblueprints.append(element)

        blueprint = OAuth2ConsumerBlueprint(
            provider_row.provider_name, __name__,
            client_id=provider_row.oauth_client_id,
            client_secret=provider_row.oauth_client_secret,
            base_url=provider_row.api_base_url,
            authorization_url=provider_row.authorization_url,
            token_url=provider_row.token_url,
            scope=scopes,
        )
        element['blueprint'] = blueprint
        element['blueprint'].backend = OAuthBackend(ub.OAuth, ub.session, str(provider_row.id),
                                                    user=current_user, user_required=True)
        app.register_blueprint(blueprint, url_prefix="/login")
        if provider_row.active:
            register_oauth_blueprint(provider_row.id, provider_row.provider_name)
    return oauthblueprints


if ub.oauth_support:
    oauthblueprints = generate_oauth_blueprints()

    @oauth_authorized.connect
    def oauth_logged_in(blueprint, token):
        provider = next((p for p in oauthblueprints if p['blueprint'] is blueprint), None)
        if not provider:
            return False
        if not token:
            flash(_("Failed to log in with %(provider)s.", provider=provider['provider_name']), category="error")
            log.error("Failed to log in with %s", provider['provider_name'])
            return False
        resp = blueprint.session.get(provider['user_info_endpoint'])
        if not resp.ok:
            flash(_("Failed to fetch user info from %(provider)s.", provider=provider['provider_name']),
                  category="error")
            log.error("Failed to fetch user info from %s", provider['provider_name'])
            return False
        user_info = resp.json()
        user_id = str(user_info[provider['user_id_field']])
        oauth_update_token(str(provider['id']), token, user_id)
        # Return the bind/login response so Flask-Dance uses it instead of a default redirect
        return bind_oauth_or_register(provider['id'], user_id,
                                      provider['provider_name'] + '.login',
                                      provider['provider_name'])

    @oauth_error.connect
    def oauth_error_handler(blueprint, error, error_description=None, error_uri=None):
        msg = (
            "OAuth error from {name}! "
            "error={error} description={description} uri={uri}"
        ).format(
            name=blueprint.name,
            error=error,
            description=error_description,
            uri=error_uri,
        )  # ToDo: Translate
        flash(msg, category="error")


@oauth.route('/link/<provider_name>')
@oauth_required
def provider_login(provider_name):
    provider = next((p for p in oauthblueprints if p['provider_name'] == provider_name), None)
    if not provider:
        abort(404)
    if not provider['blueprint'].session.authorized:
        return redirect(url_for(provider_name + '.login'))
    try:
        resp = provider['blueprint'].session.get(provider['user_info_endpoint'])
        if resp.ok:
            user_info = resp.json()
            return bind_oauth_or_register(provider['id'], str(user_info[provider['user_id_field']]),
                                          provider_name + '.login', provider_name)
        flash(_("%(provider)s Oauth error, please retry later.", provider=provider_name), category="error")
        log.error("%s Oauth error, please retry later", provider_name)
    except (InvalidGrantError, TokenExpiredError) as e:
        flash(_("%(provider)s Oauth error: %(error)s", provider=provider_name, error=e), category="error")
        log.error(e)
    return redirect(url_for('web.login'))


@oauth.route('/unlink/<provider_name>', methods=["GET"])
@user_login_required
def provider_login_unlink(provider_name):
    provider = next((p for p in oauthblueprints if p['provider_name'] == provider_name), None)
    if not provider:
        abort(404)
    return unlink_oauth(provider['id'])
