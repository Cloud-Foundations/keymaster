  function singleOktaPoll() {
      var xhr = new XMLHttpRequest();
      xhr.onreadystatechange = function() {
          if (this.readyState == 4 && this.status == 200) {
              // Action to be performed when the document is read;
	      var destination = document.getElementById("login_destination_input").getAttribute("value");
              window.location.href = destination;
          }
      };
      xhr.open("GET", "/api/v0/oktaPollCheck", true);
      xhr.send();   
  }

  function startOktaPoll() {
      console.log("start of okta poll");
      poller = setInterval(singleOktaPoll, 1500);
      var startPushButton = document.getElementById("start_okta_push_button")
      if (startPushButton) {
          startPushButton.addEventListener('click', startOktaPush, false);
	  setTimeout(startOktaPush,6000)
      } else {
	  startOktaPush();
      }
      setTimeout(clearInterval,60000, poller)
  }

  function startOktaPush() {
      var xhr = new XMLHttpRequest();
      xhr.onreadystatechange = function() {
          if (this.readyState == 4 && this.status == 200) {
              // Action to be performed when the document is read;
              console.log("success okta push start")
          }
      };
      xhr.open("GET", "/api/v0/oktaPushStart", true);
      xhr.send();   
  }

document.addEventListener('DOMContentLoaded', function () {
	  //document.getElementById('auth_button').addEventListener('click', sign);
	  startOktaPoll();
});
