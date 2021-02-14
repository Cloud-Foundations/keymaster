package eventnotifier

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/keymaster/proto/eventmon"
)

const (
	bufferLength = 16
)

func newEventNotifier(logger log.DebugLogger) *EventNotifier {
	channels := make(map[chan<- eventmon.EventV0]chan<- eventmon.EventV0)
	return &EventNotifier{
		logger:           logger,
		transmitChannels: channels,
	}
}

func (n *EventNotifier) publishAuthEvent(authType, username string) {
	transmitData := eventmon.EventV0{
		Type:     eventmon.EventTypeAuth,
		AuthType: authType,
		Username: username,
	}
	n.transmitEvent(transmitData)
}

func (n *EventNotifier) publishCert(certType string, certData []byte) {
	transmitData := eventmon.EventV0{Type: certType, CertData: certData}
	n.mutex.Lock()
	defer n.mutex.Unlock()
	for ch := range n.transmitChannels {
		select {
		case ch <- transmitData:
		default:
		}
	}
}

func (n *EventNotifier) publishServiceProviderLoginEvent(url, username string) {
	transmitData := eventmon.EventV0{
		Type:               eventmon.EventTypeServiceProviderLogin,
		ServiceProviderUrl: url,
		Username:           username,
	}
	n.transmitEvent(transmitData)
}

func (n *EventNotifier) publishWebLoginEvent(username string) {
	transmitData := eventmon.EventV0{
		Type:     eventmon.EventTypeWebLogin,
		Username: username,
	}
	n.transmitEvent(transmitData)
}

func (n *EventNotifier) publishVIPAuthEvent(vipAuthType, username string) {
	transmitData := eventmon.EventV0{
		Type:        eventmon.EventTypeAuth,
		AuthType:    eventmon.AuthTypeSymantecVIP,
		VIPAuthType: vipAuthType,
		Username:    username,
	}
	n.transmitEvent(transmitData)
}

func (n *EventNotifier) serveHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != "CONNECT" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	conn, bufRw, err := hijacker.Hijack()
	if err != nil {
		n.logger.Println("eventmon hijacking ", req.RemoteAddr, ": ",
			err.Error())
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	defer bufRw.Flush()
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			n.logger.Println("error setting keepalive: ", err.Error())
			return
		}
		if err := tcpConn.SetKeepAlivePeriod(time.Minute * 5); err != nil {
			n.logger.Println("error setting keepalive period: ",
				err.Error())
			return
		}
	}
	_, err = io.WriteString(conn, "HTTP/1.0 "+eventmon.ConnectString+"\n\n")
	if err != nil {
		n.logger.Println("error writing connect message: ", err.Error())
		return
	}
	n.logger.Println("eventmon client connected")
	n.handleConnection(bufRw)
}

func (n *EventNotifier) handleConnection(rw *bufio.ReadWriter) {
	transmitChannel := make(chan eventmon.EventV0, bufferLength)
	closeChannel := getCloseNotifier(rw)
	n.mutex.Lock()
	n.transmitChannels[transmitChannel] = transmitChannel
	n.mutex.Unlock()
	defer func() {
		n.mutex.Lock()
		delete(n.transmitChannels, transmitChannel)
		n.mutex.Unlock()
	}()
	for {
		select {
		case transmitData := <-transmitChannel:
			if err := transmitV0(rw, transmitData); err != nil {
				n.logger.Println(err)
				return
			}
		case err := <-closeChannel:
			if err == io.EOF {
				n.logger.Println("eventmon client disconnected")
				return
			}
			n.logger.Println(err)
			return
		}
		if err := rw.Flush(); err != nil {
			n.logger.Println(err)
			return
		}
	}
}

func (n *EventNotifier) transmitEvent(event eventmon.EventV0) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	for ch := range n.transmitChannels {
		select {
		case ch <- event:
		default:
		}
	}
}

func transmitV0(writer io.Writer, event eventmon.EventV0) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "   ")
	return encoder.Encode(event)
}

func getCloseNotifier(reader io.Reader) <-chan error {
	closeChannel := make(chan error)
	go func() {
		for {
			buf := make([]byte, 1)
			if _, err := reader.Read(buf); err != nil {
				closeChannel <- err
				return
			}
		}
	}()
	return closeChannel
}
