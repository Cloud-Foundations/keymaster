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

document.addEventListener('DOMContentLoaded', function () {
	  //document.getElementById('auth_button').addEventListener('click', sign);
	  sign();
});
