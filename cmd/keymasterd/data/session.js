user = document.getElementById("session-data").getAttribute("user");
date = parseInt(document.getElementById("session-data").getAttribute("date"));
expirationTime = new Date(date*1000);
document.write("<b title=\"Session expires: ", expirationTime.toString(), "\">", user, "</b>");
