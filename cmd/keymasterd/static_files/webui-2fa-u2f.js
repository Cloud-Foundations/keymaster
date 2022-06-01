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

function serverError(data) {
    console.log(data);
    alert('Server error code ' + data.status + ': ' + data.responseText);
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
    $.post('/u2f/SignResponse', JSON.stringify(resp)).done(function() {
      //alert('Success');
      var destination = document.getElementById("login_destination_input").getAttribute("value");
      window.location.href = destination;
    }).fail(serverError);
  }
  function sign() {
     document.getElementById('auth_action_text').style.display="block";
    $.getJSON('/u2f/SignRequest').done(function(req) {
      console.log(req);
      u2f.sign(req.appId, req.challenge, req.registeredKeys, u2fSigned, 45);
    }).fail(serverError);
  }



function webAuthnAuthenticateUser2() {
  console.log("top of webAuthnAuthenticateUser2");
  $.get(
    '/webauthn/AuthBegin/',
    null,
    function (data) {
      return data
    },
    'json')
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
      $.post(
        '/webauthn/AuthFinish/',
        JSON.stringify({
          id: assertion.id,
          rawId: bufferEncode(rawId),
          type: assertion.type,
          response: {
            authenticatorData: bufferEncode(authData),
            clientDataJSON: bufferEncode(clientDataJSON),
            signature: bufferEncode(sig),
            userHandle: bufferEncode(userHandle),
          },
        }),
        function (data) {
	  console.log("on post with some data " + data)
	  var destination = document.getElementById("login_destination_input").getAttribute("value");
          window.location.href = destination;
          return data;
        },
        'json')
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
