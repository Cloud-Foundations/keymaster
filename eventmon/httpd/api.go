package httpd

import (
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/Cloud-Foundations/keymaster/eventmon/eventrecorder"
	"github.com/Cloud-Foundations/keymaster/eventmon/monitord"
)

type HtmlWriter interface {
	WriteHtml(writer io.Writer)
}

var htmlWriters []HtmlWriter

type state struct {
	eventRecorder *eventrecorder.EventRecorder
	monitor       *monitord.Monitor
}

func StartServer(portNum uint, eventRecorder *eventrecorder.EventRecorder,
	monitor *monitord.Monitor, daemon bool) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", portNum))
	if err != nil {
		return err
	}
	myState := state{eventRecorder, monitor}
	http.HandleFunc("/", myState.statusHandler)
	http.HandleFunc("/showActivity", myState.showActivityHandler)
	if daemon {
		go http.Serve(listener, nil)
	} else {
		http.Serve(listener, nil)
	}
	return nil
}

func AddHtmlWriter(htmlWriter HtmlWriter) {
	htmlWriters = append(htmlWriters, htmlWriter)
}
