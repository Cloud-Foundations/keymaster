package main

import (
	"bufio"
	"fmt"
	"net/http"

	"github.com/Cloud-Foundations/Dominator/lib/html"
)

type adminDashboardType struct {
	htmlWriter html.HtmlWriter
	ready      bool
	publicLogs bool
}

func newAdminDashboard(htmlWriter html.HtmlWriter, publicLogs bool) *adminDashboardType {
	return &adminDashboardType{
		htmlWriter: htmlWriter,
		publicLogs: publicLogs,
	}
}

func (dashboard *adminDashboardType) ServeHTTP(w http.ResponseWriter,
	req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	writer := bufio.NewWriter(w)
	defer writer.Flush()
	setSecurityHeaders(w)
	fmt.Fprintln(writer, "<title>keymaster status page</title>")
	fmt.Fprintln(writer, "<body>")
	fmt.Fprintln(writer, "<center>")
	fmt.Fprintln(writer, "<h1>keymaster status page</h1>")
	fmt.Fprintln(writer, "</center>")
	html.WriteHeaderWithRequest(writer, req)
	fmt.Fprintln(writer, "<h3>")
	if dashboard.ready {
		fmt.Fprintln(writer,
			`Keymaster is <font color="green">ready</font><br>`)
	} else {
		fmt.Fprintln(writer, `Keymaster is <font color="red">sealed</font><br>`)
	}
	if dashboard.publicLogs {
		dashboard.htmlWriter.WriteHtml(writer)
	}
	fmt.Fprintln(writer, "</h3>")
	fmt.Fprintln(writer, "<hr>")
	if Version != "" {
		fmt.Fprintf(writer, "Keymasterd version: %s <br>", Version)
	}
	html.WriteFooter(writer)
	fmt.Fprintln(writer, "</body>")
}

func (dashboard *adminDashboardType) setReady() {
	dashboard.ready = true
}
