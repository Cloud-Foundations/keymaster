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
  function u2fRegistered(resp) {
    var username = document.getElementById('username').textContent;
    console.log(resp);
    if (checkError(resp)) {
      return;
    }
    fetchPostJSON('/u2f/RegisterResponse/' + encodeURIComponent(username), resp, function() {
      alert('Success');
      location.reload();
    });
  }
  function register() {
    var username = document.getElementById('username').textContent;
    document.getElementById('register_action_text').style.display="block";
    fetchGetJSON('/u2f/RegisterRequest/' + encodeURIComponent(username), function(req) {
      console.log(req);
      if (req.registeredKeys == null) {
	      req.registeredKeys = [];
      }
      u2f.register(req.appId, req.registerRequests, req.registeredKeys, u2fRegistered, 30);
    });
  }
  function u2fSigned(resp) {
    document.getElementById('auth_action_text').style.display="none";
    console.log(resp);
    if (checkError(resp)) {
      return;
    }
    fetchPostJSON('/u2f/SignResponse', resp, function() {
      alert('Success');
    });
  }
  function sign() {
     document.getElementById('auth_action_text').style.display="block";
    fetchGetJSON('/u2f/SignRequest', function(req) {
      console.log(req);
      u2f.sign(req.appId, req.challenge, req.registeredKeys, u2fSigned, 30);
    });
  }

document.addEventListener('DOMContentLoaded', function () {
	  //document.getElementById('auth_button').addEventListener('click', sign);
	  document.getElementById('register_button').addEventListener('click', register);
	  //  main();
});
