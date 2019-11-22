package eventrecorder

import (
	"bufio"
	"crypto/x509"
	"encoding/gob"
	"os"
	"syscall"
	"time"

	"github.com/Cloud-Foundations/Dominator/lib/fsutil"
	"github.com/Cloud-Foundations/Dominator/lib/log"
	"golang.org/x/crypto/ssh"
)

const (
	bufferLength = 16
	filePerms    = syscall.S_IRUSR | syscall.S_IWUSR | syscall.S_IRGRP |
		syscall.S_IROTH
	durationMonth = time.Hour * 24 * 31
)

func newEventRecorder(filename string, logger log.Logger) (
	*EventRecorder, error) {
	eventsMap, err := loadEvents(filename)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	authChannel := make(chan *AuthInfo, bufferLength)
	requestEventsChannel := make(chan chan<- Events, bufferLength)
	serviceProviderLoginChannel := make(chan *SPLoginInfo, bufferLength)
	sshCertChannel := make(chan *ssh.Certificate, bufferLength)
	webLoginChannel := make(chan string, bufferLength)
	x509CertChannel := make(chan *x509.Certificate, bufferLength)
	sr := &EventRecorder{
		filename:                    filename,
		logger:                      logger,
		eventsMap:                   eventsMap,
		AuthChannel:                 authChannel,
		RequestEventsChannel:        requestEventsChannel,
		ServiceProviderLoginChannel: serviceProviderLoginChannel,
		SshCertChannel:              sshCertChannel,
		WebLoginChannel:             webLoginChannel,
		X509CertChannel:             x509CertChannel,
	}
	go sr.eventLoop(authChannel, requestEventsChannel,
		serviceProviderLoginChannel, sshCertChannel, webLoginChannel,
		x509CertChannel)
	return sr, nil
}

func loadEvents(filename string) (map[string]*eventsListType, error) {
	file, err := os.Open(filename)
	if err != nil {
		return make(map[string]*eventsListType), err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	decoder := gob.NewDecoder(reader)
	var events EventsMap
	if err := decoder.Decode(&events); err != nil {
		return nil, err
	}
	eventsMap := make(map[string]*eventsListType, len(events))
	minCreateTime := uint64(time.Now().Add(-durationMonth).Unix())
	for username, eventsSlice := range events {
		eventsList := &eventsListType{}
		for _, savedEvent := range eventsSlice {
			if savedEvent.CreateTime < minCreateTime {
				continue
			}
			event := &eventType{
				EventType: savedEvent,
				older:     eventsList.newest,
			}
			if eventsList.newest != nil {
				eventsList.newest.newer = event
			}
			eventsList.newest = event
			if eventsList.oldest == nil {
				eventsList.oldest = event
			}
		}
		eventsMap[username] = eventsList
	}
	return eventsMap, nil
}

func (sr *EventRecorder) eventLoop(authChannel <-chan *AuthInfo,
	requestEventsChannel <-chan chan<- Events,
	serviceProviderLoginChannel <-chan *SPLoginInfo,
	sshCertChannel <-chan *ssh.Certificate, webLoginChannel <-chan string,
	x509CertChannel <-chan *x509.Certificate) {
	var lastEvents *Events
	sr.getEventsList(&lastEvents)
	hourlyTimer := time.NewTimer(time.Hour)
	saveTimer := time.NewTimer(time.Hour)
	saveTimer.Stop()
	for {
		select {
		case auth := <-authChannel:
			saveTimer.Reset(time.Second * 5)
			lastEvents = nil
			sr.recordAuthEvent(auth.Username, auth.AuthType, auth.VIPAuthType)
		case spLogin := <-serviceProviderLoginChannel:
			saveTimer.Reset(time.Second * 5)
			lastEvents = nil
			sr.recordSPLoginEvent(spLogin.Username, spLogin.URL)
		case cert := <-sshCertChannel:
			saveTimer.Reset(time.Second * 5)
			lastEvents = nil
			sr.recordCertEvent(cert.ValidPrincipals[0],
				time.Until(time.Unix(int64(cert.ValidBefore), 0)),
				true, false)
		case username := <-webLoginChannel:
			saveTimer.Reset(time.Second * 5)
			lastEvents = nil
			sr.recordWebLoginEvent(username)
		case cert := <-x509CertChannel:
			saveTimer.Reset(time.Second * 5)
			lastEvents = nil
			sr.recordCertEvent(cert.Subject.CommonName,
				time.Until(cert.NotAfter), false, true)
		case <-hourlyTimer.C:
			hourlyTimer.Reset(time.Hour)
			if sr.expireOldEvents() {
				saveTimer.Reset(time.Second * 5)
				lastEvents = nil
			}
		case replyChannel := <-requestEventsChannel:
			select { // Non-blocking.
			case replyChannel <- *sr.getEventsList(&lastEvents):
			default:
			}
		case <-saveTimer.C:
			sr.getEventsList(&lastEvents)
			if err := saveEvents(sr.filename, lastEvents.Events); err != nil {
				sr.logger.Println(err)
			}
		}
	}
}

func (sr *EventRecorder) recordAuthEvent(username string, authType uint,
	vipAuthType uint8) {
	event := &eventType{EventType: EventType{
		AuthType:    authType,
		VIPAuthType: vipAuthType},
	}
	sr.recordEvent(username, event)
}

func (sr *EventRecorder) recordCertEvent(username string,
	lifetime time.Duration, ssh, x509 bool) {
	lifetimeSeconds := uint32(lifetime.Seconds() + 0.5)
	if lifetimeSeconds >= 3600 {
		hours := lifetimeSeconds / 3600
		hoursPlus := (lifetimeSeconds + 60) / 3600
		if hoursPlus > hours {
			lifetimeSeconds = hoursPlus * 3600
		}
	} else if lifetimeSeconds >= 60 {
		minutes := lifetimeSeconds / 60
		minutesPlus := (lifetimeSeconds + 1) / 60
		if minutesPlus > minutes {
			lifetimeSeconds = minutesPlus * 60
		}
	}
	event := &eventType{
		EventType: EventType{
			LifetimeSeconds: lifetimeSeconds,
			Ssh:             ssh,
			X509:            x509,
		},
	}
	sr.recordEvent(username, event)
}

func (sr *EventRecorder) recordEvent(username string, event *eventType) {
	eventsList := sr.eventsMap[username]
	if eventsList == nil {
		eventsList = &eventsListType{}
		sr.eventsMap[username] = eventsList
	}
	event.CreateTime = uint64(time.Now().Unix())
	event.older = eventsList.newest
	if eventsList.newest != nil {
		eventsList.newest.newer = event
	}
	eventsList.newest = event
	if eventsList.oldest == nil {
		eventsList.oldest = event
	}
}

func (sr *EventRecorder) recordSPLoginEvent(username, url string) {
	event := &eventType{EventType: EventType{ServiceProviderUrl: url}}
	sr.recordEvent(username, event)
}

func (sr *EventRecorder) recordWebLoginEvent(username string) {
	event := &eventType{EventType: EventType{WebLogin: true}}
	sr.recordEvent(username, event)
}

func (sr *EventRecorder) getEventsList(lastEvents **Events) *Events {
	if *lastEvents != nil {
		return *lastEvents
	}
	startTime := time.Now()
	eventsMap := make(map[string][]EventType, len(sr.eventsMap))
	for username, eventsList := range sr.eventsMap {
		events := make([]EventType, 0)
		for event := eventsList.newest; event != nil; event = event.older {
			events = append(events, event.EventType)
		}
		eventsMap[username] = events
	}
	*lastEvents = &Events{time.Since(startTime), eventsMap}
	return *lastEvents
}

func saveEvents(filename string, eventsMap EventsMap) error {
	file, err := fsutil.CreateRenamingWriter(filename, filePerms)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	defer writer.Flush()
	encoder := gob.NewEncoder(writer)
	if err := encoder.Encode(eventsMap); err != nil {
		return err
	}
	return nil
}

func (sr *EventRecorder) expireOldEvents() bool {
	minCreateTime := uint64(time.Now().Add(-durationMonth).Unix())
	changed := false
	for _, eventsList := range sr.eventsMap {
		for event := eventsList.oldest; event != nil; event = event.newer {
			if event.CreateTime >= minCreateTime {
				break
			}
			eventsList.oldest = event.newer
			if event.newer == nil {
				eventsList.newest = nil
			} else {
				event.newer.older = nil
			}
			changed = true
		}
	}
	return changed
}
