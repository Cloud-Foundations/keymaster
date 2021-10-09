package main

import (
	"net/http"
	"path"
)

type scriptData struct {
	script []byte
}

var compiledScripts = map[string]string{
	"session.js": `
user = document.getElementById("session-data").getAttribute("user");
date = parseInt(document.getElementById("session-data").getAttribute("date"));
expirationTime = new Date(date*1000);
document.write("<b title=\"Session expires: ", expirationTime.toString(), "\">", user, "</b>");
`,
}

func registerJavaScriptHandlers(mux *http.ServeMux) {
	basePath := path.Join("/static/compiled")
	for name, script := range compiledScripts {
		mux.Handle(path.Join(basePath, name), &scriptData{[]byte(script)})
	}
}

func (sd *scriptData) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/javascript; charset=utf-8")
	w.Write(sd.script)
}
