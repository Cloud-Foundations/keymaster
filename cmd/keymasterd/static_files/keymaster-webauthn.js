
// cviecco notes: this comes inspired from https://www.herbie.dev/blog/webauthn-basic-web-client-server/
// and requires jquery... we should be thinking on removing jquery dependency


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



function webAuthnRegisterUser() {

	var username = document.getElementById('username').textContent;
	$.get(
	  '/webauthn/RegisterRequest/' + username,
	  null,
	  function (data) {
		return data
	  },
	  'json')
	  .then((credentialCreationOptions) => {
		  // TODO
		  //alert(credentialCreationOptions);
		  console.log(credentialCreationOptions);
		  credentialCreationOptions.publicKey.challenge = bufferDecode(credentialCreationOptions.publicKey.challenge);
                  credentialCreationOptions.publicKey.user.id = bufferDecode(credentialCreationOptions.publicKey.user.id);
                  credentialCreationOptions.publicKey.authenticatorSelection.userVerification="discouraged";
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

                  $.post(
                    '/webauthn/RegisterFinish/' + username,
                    JSON.stringify({
                       id: credential.id,
                       rawId: bufferEncode(rawId),
                       type: credential.type,
                       response: {
                          attestationObject: bufferEncode(attestationObject),
                          clientDataJSON: bufferEncode(clientDataJSON),
                       },
                    }),
                    function (data) {
                        return data
                     },
                    'json')

          })
          .then((success) => {
                  alert("successfully registered " + username + "!")
                  return
          })
          .catch((error) => {
          console.log(error)
          alert("failed to register " + username)
          });
}

function webAuthnAuthenticateUser() {

  var username = document.getElementById('username').textContent;

  $.get(
    '/webauthn/AuthBegin/' + username,
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
      //credentialRequestOptions.publicKey.authenticatorSelection.userVerification="discouraged";

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
        '/webauthn/AuthFinish/' + username,
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
	  console.log("Authnenticated: " + data);
          alert("successfully authenticated " + username + "!");
          return data
        },
        'json')
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
