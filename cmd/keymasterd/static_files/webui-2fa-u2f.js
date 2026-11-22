// Base64 to ArrayBuffer
function bufferDecode(value) {
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

// ArrayBuffer to URLBase64
function bufferEncode(value) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");;
}

function getSafeLoginDestination() {
  var input = document.getElementById("login_destination_input");
  var rawDest = input ? input.getAttribute("value") : "";
  if (!rawDest) {
    return "/profile/";
  }
  try {
    var parsed = new URL(rawDest, window.location.origin);
    if ((parsed.protocol === "http:" || parsed.protocol === "https:") &&
        parsed.origin === window.location.origin) {
      var segments = parsed.pathname.split("/");
      var safeSegments = [];
      for (var i = 0; i < segments.length; i++) {
        safeSegments.push(encodeURIComponent(decodeURIComponent(segments[i])));
      }
      var safePath = safeSegments.join("/");
      if (!safePath.startsWith("/") || safePath.startsWith("//")) {
        return "/profile/";
      }

      var queryParts = [];
      parsed.searchParams.forEach(function (val, key) {
        queryParts.push(encodeURIComponent(key) + "=" + encodeURIComponent(val));
      });
      var safeSearch = queryParts.length > 0 ? "?" + queryParts.join("&") : "";

      var safeHash = "";
      if (parsed.hash && parsed.hash.length > 1) {
        safeHash = "#" + encodeURIComponent(decodeURIComponent(parsed.hash.slice(1)));
      }

      return safePath + safeSearch + safeHash;
    }
  } catch (e) {
    // Fall back on parse error
  }
  return "/profile/";
}

function serverError(data) {
    console.log(data);
    var status = data && data.status ? data.status : 'network';
    var text = data && data.responseText !== undefined ? data.responseText : data;
    alert('Server error code ' + status + ': ' + text);
  }

function fetchGetJSON(url, onSuccess) {
    fetch(url, {
      headers: { 'Accept': 'application/json' }
    })
      .then(function(response) {
        if (!response.ok) {
          return response.text().then(function(text) {
            throw { status: response.status, responseText: text };
          });
        }
        return response.json();
      })
      .then(onSuccess)
      .catch(serverError);
  }

function fetchPostJSON(url, bodyObj, onSuccess) {
    fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(bodyObj)
    })
      .then(function(response) {
        if (!response.ok) {
          return response.text().then(function(text) {
            throw { status: response.status, responseText: text };
          });
        }
        return response;
      })
      .then(onSuccess)
      .catch(serverError);
  }

function checkError(resp) {
    if (!('errorCode' in resp)) {
      return false;
    }
    //if (resp.errorCode === u2f.ErrorCodes['OK']) {
    if (resp.errorCode == 0) {
      return false;
    }
    var msg = 'U2F error code ' + resp.errorCode;
    for (name in u2f.ErrorCodes) {
      if (u2f.ErrorCodes[name] === resp.errorCode) {
        msg += ' (' + name + ')';
      }
    }
    if (resp.errorMessage) {
      msg += ': ' + resp.errorMessage;
    }
    console.log(msg);
    alert(msg);
    return true;
  }
  function hideAllU2FElements() {
      document.getElementById('auth_action_text').style.display="none";
      var manualStartVipDiv = document.getElementById("manual_start_vip_div")
      if (manualStartVipDiv) {
	      manualStartVipDiv.style.display="none";
      }
      var otpOrU2fMessageDiv = document.getElementById("otp_or_u2f_message")
      if (otpOrU2fMessageDiv) {
              otpOrU2fMessageDiv.style.display="none";
      }
  }

  function u2fSigned(resp) {
    //document.getElementById('auth_action_text').style.display="none";
    hideAllU2FElements();
    //console.log(resp);
    if (checkError(resp)) {
      return;
    }
    fetchPostJSON('/u2f/SignResponse', resp, function() {
      //alert('Success');
      window.location.href = getSafeLoginDestination();
    });
  }
  function sign() {
     document.getElementById('auth_action_text').style.display="block";
    fetchGetJSON('/u2f/SignRequest', function(req) {
      console.log(req);
      u2f.sign(req.appId, req.challenge, req.registeredKeys, u2fSigned, 45);
    });
  }



function webAuthnAuthenticateUser2() {
  console.log("top of webAuthnAuthenticateUser2");
  fetch('/webauthn/AuthBegin/', {
    headers: { 'Accept': 'application/json' }
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error('Server returned HTTP ' + response.status);
      }
      return response.json();
    })
    .then((credentialRequestOptions) => {
      credentialRequestOptions.publicKey.challenge = bufferDecode(credentialRequestOptions.publicKey.challenge);
      credentialRequestOptions.publicKey.allowCredentials.forEach(function (listItem) {
        listItem.id = bufferDecode(listItem.id)
      });

      return navigator.credentials.get({
        publicKey: credentialRequestOptions.publicKey
      })
    })
    .then((assertion) => {

      let authData = assertion.response.authenticatorData;
      let clientDataJSON = assertion.response.clientDataJSON;
      let rawId = assertion.rawId;
      let sig = assertion.response.signature;
      let userHandle = assertion.response.userHandle;
      return fetch('/webauthn/AuthFinish/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          id: assertion.id,
          rawId: bufferEncode(rawId),
          type: assertion.type,
          response: {
            authenticatorData: bufferEncode(authData),
            clientDataJSON: bufferEncode(clientDataJSON),
            signature: bufferEncode(sig),
            userHandle: bufferEncode(userHandle),
          },
        })
      }).then((response) => {
        if (!response.ok) {
          throw new Error('Server returned HTTP ' + response.status);
        }
        window.location.href = getSafeLoginDestination();
        return response.json();
      });
    })
    .then((success) => {
      console.log("successfully pressed button");
      //hideAllU2FElements();
    })
    .catch((error) => {
      console.log(error)
      alert("failed to authenticate ")
    });
}


document.addEventListener('DOMContentLoaded', function () {
	  webAuthnAuthenticateUser2();
});
