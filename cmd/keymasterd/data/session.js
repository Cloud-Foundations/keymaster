function showSessionExpiration() {
    date = parseInt(document.getElementById("session-data").getAttribute("date"));
    expirationTime = new Date(date*1000);
    titleText = "Session expires: "+expirationTime.toString();
    authUsername.setAttribute("title", titleText);
}

document.addEventListener('DOMContentLoaded', function () {
    showSessionExpiration();
});
