package httpd

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/Cloud-Foundations/Dominator/lib/format"
	"github.com/Cloud-Foundations/Dominator/lib/html"
	"github.com/Cloud-Foundations/keymaster/eventmon/eventrecorder"
)

const (
	durationDay   = time.Hour * 24
	durationWeek  = durationDay * 7
	durationMonth = durationDay * 31
)

type counterType struct {
	authPassword        uint64
	authSymantecVIPotp  uint64
	authSymantecVIPpush uint64
	authU2F             uint64
	authTOTP            uint64
	spLogin             uint64
	ssh                 uint64
	webLogin            uint64
	x509                uint64
}

func (s state) showActivityHandler(w http.ResponseWriter, req *http.Request) {
	writer := bufio.NewWriter(w)
	defer writer.Flush()
	fmt.Fprintln(writer, "<title>keymaster-eventmond activity report</title>")
	fmt.Fprintln(writer, `<style>
                          table, th, td {
                          border-collapse: collapse;
                          }
                          </style>`)
	fmt.Fprintln(writer, "<body>")
	fmt.Fprintln(writer, "<center>")
	fmt.Fprintln(writer, "<h1>keymaster-eventmond activity report</h1>")
	fmt.Fprintln(writer, "</center>")
	eventsChannel := make(chan eventrecorder.Events, 1)
	s.eventRecorder.RequestEventsChannel <- eventsChannel
	eventsMap := <-eventsChannel
	startTime := time.Now()
	usernames := make([]string, 0, len(eventsMap.Events))
	for username := range eventsMap.Events {
		if len(eventsMap.Events[username]) > 0 {
			usernames = append(usernames, username)
		}
	}
	sort.Strings(usernames)
	s.writeActivity(writer, usernames, eventsMap.Events)
	fmt.Fprintln(writer, "<br>")
	s.writeSPLoginActivity(writer, eventsMap.Events)
	renderTime := time.Since(startTime)
	fmt.Fprintf(writer,
		"<br><font color=\"grey\">Fetch time: %s render time: %s</font>\n",
		format.Duration(eventsMap.ComputeTime), format.Duration(renderTime))
	fmt.Fprintln(writer, "<hr>")
	html.WriteFooter(writer)
	fmt.Fprintln(writer, "</body>")
}

func (s state) writeActivity(writer io.Writer, usernames []string,
	eventsMap eventrecorder.EventsMap) {
	fmt.Fprintln(writer,
		"SPlogin/SSH/Web/X509 Password/VIPotp/VIPpush/U2F/TOTP")
	fmt.Fprintln(writer, `<table border="1" style="width:100%">`)
	fmt.Fprintln(writer, "  <tr>")
	fmt.Fprintln(writer, "    <th>Username</th>")
	fmt.Fprintln(writer, "    <th>Last Day</th>")
	fmt.Fprintln(writer, "    <th>Last Week</th>")
	fmt.Fprintln(writer, "    <th>Last Month</th>")
	fmt.Fprintln(writer, "    <th>Min Lifetime</th>")
	fmt.Fprintln(writer, "    <th>Med Lifetime</th>")
	fmt.Fprintln(writer, "    <th>Max Lifetime</th>")
	fmt.Fprintln(writer, "  </tr>")
	totals := &statsType{minLifetime: durationMonth * 120, maxLifetime: -1}
	for _, username := range usernames {
		writeUser(writer, username, eventsMap[username], time.Now(), totals)
	}
	totals.writeHtml(writer, fmt.Sprintf("<b>ALL %d USERS</b>", len(usernames)))
	fmt.Fprintln(writer, "</table>")
}

func (s state) writeSPLoginActivity(writer io.Writer,
	eventsMap eventrecorder.EventsMap) {
	urlToCountTable := make(map[string]uint64)
	for _, events := range eventsMap {
		for _, event := range events {
			if rawURL := event.ServiceProviderUrl; rawURL != "" {
				var URL string
				if u, err := url.Parse(rawURL); err != nil {
					URL = rawURL
				} else {
					if len(u.Port()) > 0 {
						URL = u.Scheme + "://" + u.Hostname() + ":" + u.Port() +
							"/"
					} else {
						URL = u.Scheme + "://" + u.Hostname() + "/"
					}
				}
				urlToCountTable[URL] = urlToCountTable[URL] + 1
			}
		}
	}
	var pairs stringCountPairs
	for url, count := range urlToCountTable {
		pairs = append(pairs, stringCountPair{url, count})
	}
	sort.Sort(sort.Reverse(pairs))
	fmt.Fprintln(writer, `<table border="1" style="width:100%">`)
	fmt.Fprintln(writer, "  <tr>")
	fmt.Fprintln(writer, "    <th>Service Provider URL</th>")
	fmt.Fprintln(writer, "    <th>Login Count</th>")
	fmt.Fprintln(writer, "  </tr>")
	for _, pair := range pairs {
		fmt.Fprintln(writer, "  <tr>")
		fmt.Fprintf(writer, "    <td>%s</td>\n", pair.url)
		fmt.Fprintf(writer, "    <td>%d</td>\n", pair.count)
		fmt.Fprintln(writer, "  </tr>")
	}
	fmt.Fprintln(writer, "</table>")
}

func writeUser(writer io.Writer, username string,
	events []eventrecorder.EventType, now time.Time, totals *statsType) {
	stats := &statsType{
		lifetimes:   make([]int, 0, len(events)),
		minLifetime: durationMonth * 120,
		maxLifetime: -1,
	}
	for _, event := range events {
		if event.LifetimeSeconds > 0 {
			lifetime := time.Duration(event.LifetimeSeconds) * time.Second
			stats.lifetimes = append(stats.lifetimes,
				int(event.LifetimeSeconds))
			totals.lifetimes = append(totals.lifetimes,
				int(event.LifetimeSeconds))
			if lifetime < stats.minLifetime {
				stats.minLifetime = lifetime
			}
			if lifetime > stats.maxLifetime {
				stats.maxLifetime = lifetime
			}
			if lifetime < totals.minLifetime {
				totals.minLifetime = lifetime
			}
			if lifetime > totals.maxLifetime {
				totals.maxLifetime = lifetime
			}
		}
		age := now.Sub(time.Unix(int64(event.CreateTime), 0))
		if age <= durationDay {
			stats.countOverLastDay.increment(event)
			totals.countOverLastDay.increment(event)
		}
		if age <= durationWeek {
			stats.countOverLastWeek.increment(event)
			totals.countOverLastWeek.increment(event)
		}
		if age <= durationMonth {
			stats.countOverLastMonth.increment(event)
			totals.countOverLastMonth.increment(event)
		}
	}
	stats.writeHtml(writer, username)
}

func (counter *counterType) increment(event eventrecorder.EventType) {
	switch event.AuthType {
	case eventrecorder.AuthTypePassword:
		counter.authPassword++
	case eventrecorder.AuthTypeSymantecVIP:
		switch event.VIPAuthType {
		case eventrecorder.VIPAuthTypeOTP:
			counter.authSymantecVIPotp++
		case eventrecorder.VIPAuthTypePush:
			counter.authSymantecVIPpush++
		}
	case eventrecorder.AuthTypeU2F:
		counter.authU2F++
	case eventrecorder.AuthTypeTOTP:
		counter.authTOTP++
	}
	if event.ServiceProviderUrl != "" {
		counter.spLogin++
	}
	if event.Ssh {
		counter.ssh++
	}
	if event.WebLogin {
		counter.webLogin++
	}
	if event.X509 {
		counter.x509++
	}
}

func (counter *counterType) string() string {
	return fmt.Sprintf("%d/%d/%d/%d %d/%d/%d/%d/%d",
		counter.spLogin, counter.ssh, counter.webLogin, counter.x509,
		counter.authPassword, counter.authSymantecVIPotp,
		counter.authSymantecVIPpush, counter.authU2F, counter.authTOTP)
}

type stringCountPairs []stringCountPair

type stringCountPair struct {
	url   string
	count uint64
}

func (pairs stringCountPairs) Len() int {
	return len(pairs)
}

func (pairs stringCountPairs) Less(left, right int) bool {
	return pairs[left].count < pairs[right].count
}

func (pairs stringCountPairs) Swap(left, right int) {
	pairs[left], pairs[right] = pairs[right], pairs[left]
}

type statsType struct {
	countOverLastDay   counterType
	countOverLastWeek  counterType
	countOverLastMonth counterType
	lifetimes          []int
	minLifetime        time.Duration
	maxLifetime        time.Duration
}

func (stats *statsType) writeHtml(writer io.Writer, username string) {
	fmt.Fprintf(writer, "  <tr>\n")
	fmt.Fprintf(writer, "    <td>%s</td>\n", username)
	fmt.Fprintf(writer, "    <td>%s</td>\n", stats.countOverLastDay.string())
	fmt.Fprintf(writer, "    <td>%s</td>\n", stats.countOverLastWeek.string())
	fmt.Fprintf(writer, "    <td>%s</td>\n", stats.countOverLastMonth.string())
	if len(stats.lifetimes) > 0 {
		sort.Ints(stats.lifetimes)
		medLifetime := time.Duration(
			stats.lifetimes[len(stats.lifetimes)/2]) * time.Second
		fmt.Fprintf(writer, "    <td>%s</td>\n",
			format.Duration(stats.minLifetime))
		fmt.Fprintf(writer, "    <td>%s</td>\n", format.Duration(medLifetime))
		fmt.Fprintf(writer, "    <td>%s</td>\n",
			format.Duration(stats.maxLifetime))
	} else {
		fmt.Fprintln(writer, "    <td></td>")
		fmt.Fprintln(writer, "    <td></td>")
		fmt.Fprintln(writer, "    <td></td>")
	}
	fmt.Fprintf(writer, "  </tr>\n")
}
