/* WebAuthn / passkey helpers */

function _bufToBase64url(buf) {
    var bytes = new Uint8Array(buf);
    var str = '';
    for (var i = 0; i < bytes.byteLength; i++) {
        str += String.fromCharCode(bytes[i]);
    }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function _base64urlToBuf(b64url) {
    var b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) { b64 += '='; }
    var str = atob(b64);
    var buf = new ArrayBuffer(str.length);
    var view = new Uint8Array(buf);
    for (var i = 0; i < str.length; i++) {
        view[i] = str.charCodeAt(i);
    }
    return buf;
}

function _toArrayBuffer(val) {
    if (typeof val === 'string') return _base64urlToBuf(val);
    if (val instanceof ArrayBuffer) return val;
    if (ArrayBuffer.isView(val)) return val.buffer;
    return val;
}

function _toBase64url(val) {
    if (val instanceof ArrayBuffer || ArrayBuffer.isView(val)) return _bufToBase64url(val);
    return val;
}

function _prepareRegistrationOptions(opts) {
    opts.challenge = _toArrayBuffer(opts.challenge);
    opts.user.id = _toArrayBuffer(opts.user.id);
    if (opts.excludeCredentials) {
        opts.excludeCredentials = opts.excludeCredentials.map(function(c) {
            return Object.assign({}, c, { id: _toArrayBuffer(c.id) });
        });
    }
    return opts;
}

function _prepareAuthenticationOptions(opts) {
    opts.challenge = _toArrayBuffer(opts.challenge);
    if (opts.allowCredentials) {
        opts.allowCredentials = opts.allowCredentials.map(function(c) {
            return Object.assign({}, c, { id: _toArrayBuffer(c.id) });
        });
    }
    return opts;
}

function _encodeRegistrationResponse(cred) {
    return {
        id: cred.id,
        rawId: _toBase64url(cred.rawId),
        response: {
            clientDataJSON: _toBase64url(cred.response.clientDataJSON),
            attestationObject: _toBase64url(cred.response.attestationObject)
        },
        type: cred.type
    };
}

function _encodeAuthenticationResponse(cred) {
    var resp = {
        id: cred.id,
        rawId: _toBase64url(cred.rawId),
        response: {
            authenticatorData: _toBase64url(cred.response.authenticatorData),
            clientDataJSON: _toBase64url(cred.response.clientDataJSON),
            signature: _toBase64url(cred.response.signature)
        },
        type: cred.type
    };
    if (cred.response.userHandle) {
        resp.response.userHandle = _toBase64url(cred.response.userHandle);
    }
    return resp;
}

async function passkeyRegister(name) {
    var base = (typeof getPath === 'function') ? getPath() : '';
    var beginResp = await fetch(base + '/passkey/register/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    });
    if (!beginResp.ok) {
        throw new Error('Server error starting registration');
    }
    var options = _prepareRegistrationOptions(await beginResp.json());
    var cred = await navigator.credentials.create({ publicKey: options });
    var payload = _encodeRegistrationResponse(cred);
    var completeResp = await fetch(
        base + '/passkey/register/complete?name=' + encodeURIComponent(name || 'Passkey'),
        {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        }
    );
    if (!completeResp.ok) {
        var err = await completeResp.json();
        throw new Error(err.error || 'Registration failed');
    }
    return await completeResp.json();
}

async function passkeyLogin(nextUrl) {
    var base = (typeof getPath === 'function') ? getPath() : '';
    var beginResp = await fetch(base + '/passkey/login/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    });
    if (!beginResp.ok) {
        throw new Error('Server error starting authentication');
    }
    var options = _prepareAuthenticationOptions(await beginResp.json());
    var cred = await navigator.credentials.get({ publicKey: options });
    var payload = _encodeAuthenticationResponse(cred);
    var qs = nextUrl ? '?next=' + encodeURIComponent(nextUrl) : '';
    var completeResp = await fetch(base + '/passkey/login/complete' + qs, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    if (!completeResp.ok) {
        var err = await completeResp.json();
        throw new Error(err.error || 'Authentication failed');
    }
    var result = await completeResp.json();
    if (result.redirect) {
        window.location.href = result.redirect;
    }
    return result;
}
