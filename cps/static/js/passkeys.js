/* This file is part of the Calibre-Web (https://github.com/janeczku/calibre-web)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/* global getPath */

(function () {
    "use strict";

    function supported() {
        return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
    }

    function base64urlToBuffer(value) {
        var padded = value.replace(/-/g, "+").replace(/_/g, "/");
        while (padded.length % 4) {
            padded += "=";
        }
        var binary = window.atob(padded);
        var buffer = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            buffer[i] = binary.charCodeAt(i);
        }
        return buffer.buffer;
    }

    function bufferToBase64url(buffer) {
        var bytes = new Uint8Array(buffer);
        var binary = "";
        for (var i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    function csrfToken() {
        return $("input[name='csrf_token']").first().val() || "";
    }

    function post(url, payload) {
        return $.ajax({
            url: getPath() + url,
            type: "POST",
            contentType: "application/json; charset=utf-8",
            dataType: "json",
            data: JSON.stringify(payload || {}),
            headers: { "X-CSRFToken": csrfToken() }
        });
    }

    function errorMessage(xhr, fallback) {
        try {
            var response = JSON.parse(xhr.responseText);
            if (response && response.message) {
                return response.message;
            }
        } catch (ignored) {
            // fall through to the generic message
        }
        return fallback;
    }

    // The server hands out the options with all binary fields base64url encoded
    function decodeCreationOptions(options) {
        options.challenge = base64urlToBuffer(options.challenge);
        options.user.id = base64urlToBuffer(options.user.id);
        (options.excludeCredentials || []).forEach(function (credential) {
            credential.id = base64urlToBuffer(credential.id);
        });
        return options;
    }

    function decodeRequestOptions(options) {
        options.challenge = base64urlToBuffer(options.challenge);
        (options.allowCredentials || []).forEach(function (credential) {
            credential.id = base64urlToBuffer(credential.id);
        });
        return options;
    }

    function encodeRegistration(credential) {
        return {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            authenticatorAttachment: credential.authenticatorAttachment,
            clientExtensionResults: credential.getClientExtensionResults(),
            response: {
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                attestationObject: bufferToBase64url(credential.response.attestationObject),
                transports: credential.response.getTransports ? credential.response.getTransports() : []
            }
        };
    }

    function encodeAssertion(credential) {
        return {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            authenticatorAttachment: credential.authenticatorAttachment,
            clientExtensionResults: credential.getClientExtensionResults(),
            response: {
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                authenticatorData: bufferToBase64url(credential.response.authenticatorData),
                signature: bufferToBase64url(credential.response.signature),
                userHandle: credential.response.userHandle
                    ? bufferToBase64url(credential.response.userHandle)
                    : null
            }
        };
    }

    function setStatus(text, isError) {
        var $status = $("#passkey_status");
        if (!$status.length) {
            if (text && isError) {
                alert(text);
            }
            return;
        }
        $status.text(text || "");
        $status.toggleClass("text-danger", !!isError);
    }

    function login(event) {
        event.preventDefault();
        var $button = $(this);
        if (!supported()) {
            setStatus($button.data("unsupported"), true);
            return;
        }
        $button.prop("disabled", true);
        setStatus("");

        post("/webauthn/auth/options", { username: $("#username").val() || "" })
            .then(function (options) {
                return navigator.credentials.get({ publicKey: decodeRequestOptions(options) });
            })
            .then(function (credential) {
                if (!credential) {
                    throw new Error("no credential");
                }
                return post("/webauthn/auth/verify", {
                    credential: encodeAssertion(credential),
                    next: $("input[name='next']").val() || "",
                    remember_me: $("input[name='remember_me']").is(":checked")
                });
            })
            .then(function (response) {
                window.location.href = response.redirect_url || getPath() + "/";
            })
            .catch(function (error) {
                $button.prop("disabled", false);
                if (error && error.name === "NotAllowedError") {
                    // user dismissed the browser prompt, nothing worth reporting
                    setStatus("");
                    return;
                }
                setStatus(errorMessage(error, $button.data("failed")), true);
            });
    }

    function register(event) {
        event.preventDefault();
        var $button = $(this);
        if (!supported()) {
            setStatus($button.data("unsupported"), true);
            return;
        }
        var nickname = window.prompt($button.data("prompt"), $button.data("default-name") || "");
        if (nickname === null) {
            return;
        }
        $button.prop("disabled", true);
        setStatus("");

        post("/webauthn/register/options", {})
            .then(function (options) {
                return navigator.credentials.create({ publicKey: decodeCreationOptions(options) });
            })
            .then(function (credential) {
                if (!credential) {
                    throw new Error("no credential");
                }
                return post("/webauthn/register/verify", {
                    credential: encodeRegistration(credential),
                    nickname: nickname
                });
            })
            .then(function () {
                window.location.reload();
            })
            .catch(function (error) {
                $button.prop("disabled", false);
                if (error && error.name === "NotAllowedError") {
                    setStatus("");
                    return;
                }
                setStatus(errorMessage(error, $button.data("failed")), true);
            });
    }

    function remove(event) {
        event.preventDefault();
        var $button = $(this);
        if (!window.confirm($button.data("confirm"))) {
            return;
        }
        $button.prop("disabled", true);
        post("/webauthn/credentials/" + $button.data("credential-id") + "/delete", {})
            .then(function () {
                window.location.reload();
            })
            .catch(function (error) {
                $button.prop("disabled", false);
                setStatus(errorMessage(error, $button.data("failed")), true);
            });
    }

    $(function () {
        if (!supported()) {
            $(".passkey-requires-support").hide();
            return;
        }
        $("#passkey_login").on("click", login);
        $("#passkey_register").on("click", register);
        $(document).on("click", ".passkey-delete", remove);
    });
})();
