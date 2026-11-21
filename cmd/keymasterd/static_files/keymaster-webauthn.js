
// cviecco notes: this comes inspired from https://www.herbie.dev/blog/webauthn-basic-web-client-server/


// Base64 to ArrayBuffer
function bufferDecode(value) {
    //return  Uint8Array.fromBase64(value, { alphabet: "base64url" });
    value = value.replace(/\-/g, "+").replace(/_/g, "/");
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

function bufferDecodeB64(value) {
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

// ArrayBuffer to URLBase64
function bufferEncode(value) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");;
}



function webAuthnRegisterUser() {

	var username = document.getElementById('username').textContent;
	fetch('/webauthn/RegisterRequest/' + encodeURIComponent(username), {
		headers: { 'Accept': 'application/json' }
	})
	  .then((response) => {
		  if (!response.ok) {
			  throw new Error('Server returned HTTP ' + response.status);
		  }
		  return response.json();
	  })
	  .then((credentialCreationOptions) => {
		  // TODO
		  //alert(credentialCreationOptions);
		  console.log(credentialCreationOptions);
		  credentialCreationOptions.publicKey.challenge = bufferDecode(credentialCreationOptions.publicKey.challenge);
                  credentialCreationOptions.publicKey.user.id = bufferDecode(credentialCreationOptions.publicKey.user.id);
                  // TODO: the next line was breaking Firefox. We need to investigate JS flags on issue 311
                  // For now we cooment this as does not affect functionality
                  //credentialCreationOptions.publicKey.authenticatorSelection.userVerification="discouraged";
                  console.log(credentialCreationOptions);
                  return navigator.credentials.create({
                       publicKey: credentialCreationOptions.publicKey
                  })
	  })
	  .then((credential) => {
                  // TODO
		  //alert("starting then credentials");
		  let attestationObject = credential.response.attestationObject;
                  let clientDataJSON = credential.response.clientDataJSON;
                  let rawId = credential.rawId;

                  return fetch('/webauthn/RegisterFinish/' + encodeURIComponent(username), {
                     method: 'POST',
                     headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                     },
                     body: JSON.stringify({
                        id: credential.id,
                        rawId: bufferEncode(rawId),
                        type: credential.type,
                        response: {
                           attestationObject: bufferEncode(attestationObject),
                           clientDataJSON: bufferEncode(clientDataJSON),
                        },
                     })
                  }).then((response) => {
                     if (!response.ok) {
                        throw new Error('Server returned HTTP ' + response.status);
                     }
                     return response.json();
                  });

          })
          .then((success) => {
                  alert("successfully registered " + username + "!");
		  location.reload();
                  return
          })
          .catch((error) => {
          console.log(error)
          alert("failed to register " + username)
          });
}

function webAuthnAuthenticateUser() {

  var username = document.getElementById('username').textContent;

  fetch('/webauthn/AuthBegin/' + encodeURIComponent(username), {
    headers: { 'Accept': 'application/json' }
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error('Server returned HTTP ' + response.status);
      }
      return response.json();
    })
    .then((credentialRequestOptions) => {

      credentialRequestOptions.publicKey.challenge = bufferDecodeB64(credentialRequestOptions.publicKey.challenge);
      credentialRequestOptions.publicKey.allowCredentials.forEach(function (listItem) {
        listItem.id = bufferDecodeB64(listItem.id)
      });
      //credentialRequestOptions.publicKey.authenticatorSelection.userVerification="discouraged";
      console.log("Authnenticated: " + credentialRequestOptions);
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

      return fetch('/webauthn/AuthFinish/' + encodeURIComponent(username), {
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
        alert("successfully authenticated " + username + "!");
        return response.json();
      });
    })
    .then((success) => {
      console.log("button pressed")
      return
    })
    .catch((error) => {
      console.log(error)
      alert("failed to authenticate " + username)
    });
}



document.addEventListener('DOMContentLoaded', function () {
          document.getElementById('webauthn_auth_button').addEventListener('click', webAuthnAuthenticateUser);
          document.getElementById('webauthn_register_button').addEventListener('click', webAuthnRegisterUser);
          //  main();
});
