  function singleVipPoll() {
      var xhr = new XMLHttpRequest();
      xhr.onreadystatechange = function() {
          if (this.readyState == 4 && this.status == 200) {
              // Action to be performed when the document is read;
	      var destination = document.getElementById("login_destination_input").getAttribute("value");
              window.location.href = destination;
          }
      };
      xhr.open("GET", "/api/v0/vipPollCheck", true);
      xhr.send();   
  }

  function startVipPoll() {
      console.log("start of vip poll");
      poller = setInterval(singleVipPoll, 3000);
      var startPushButton = document.getElementById("start_vip_push_button")
      if (startPushButton) {
          startPushButton.addEventListener('click', startVipPush, false);
	  setTimeout(startVipPush,6000)
      } else {
	  startVipPush();
      }
      setTimeout(clearInterval,60000, poller)
  }
  function startVipPush() {
      var xhr = new XMLHttpRequest();
      xhr.onreadystatechange = function() {
          if (this.readyState == 4 && this.status == 200) {
              // Action to be performed when the document is read;
              cosole.log("success vip push start")
          }
      };
      xhr.open("GET", "/api/v0/vipPushStart", true);
      xhr.send();   
  }

document.addEventListener('DOMContentLoaded', function () {
	  //document.getElementById('auth_button').addEventListener('click', sign);
	  startVipPoll();
});
