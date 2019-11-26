package main

import (
	"crypto/x509"
	"errors"
	"strings"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/authutil"

	"github.com/Cloud-Foundations/tricorder/go/tricorder"
	"github.com/Cloud-Foundations/tricorder/go/tricorder/units"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	dependencyLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "keymaster_dependency_check_duration_seconds",
			Help:       "Dependency latency.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"type", "name", "target"},
	)
	dependencyLastSuccessSecondsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "keymaster_dependency_durations_since_last_success_seconds",
			Help: "Seconds since last update",
		},
		[]string{"type", "name"},
	)
	lastSuccessLDAPPasswordTime time.Time
	lastSuccessLDAPUserInfoTime time.Time
)

const timeoutSecs = 5

func init() {
	prometheus.MustRegister(dependencyLatency)
	prometheus.MustRegister(dependencyLastSuccessSecondsGauge)
	tricorder.RegisterMetric(
		"keymaster/dependency_status/LDAP/PasswordDurationSinceLastSuccessfulCheck",
		func() time.Duration {
			return time.Now().Sub(lastSuccessLDAPPasswordTime)
		},
		units.Second,
		"Time since last successful LDAP check for Password(s)")
	tricorder.RegisterMetric(
		"keymaster/dependency_status/LDAP/UserinfoDurationSinceLastSuccessfulCheck",
		func() time.Duration {
			return time.Now().Sub(lastSuccessLDAPUserInfoTime)
		},
		units.Second,
		"Time since last successful LDAP check for UserInfo(s)")
}

func checkLDAPURLs(ldapURLs string, name string, rootCAs *x509.CertPool) error {
	if len(ldapURLs) <= 0 {
		return errors.New("No data to check")
	}
	urlList := strings.Split(ldapURLs, ",")
	for _, stringURL := range urlList {
		url, err := authutil.ParseLDAPURL(stringURL)
		if err != nil {
			return err
		}
		startTime := time.Now()
		err = authutil.CheckLDAPConnection(*url, timeoutSecs, rootCAs)
		if err != nil {
			continue
		}
		dependencyLatency.WithLabelValues("ldap", name, stringURL).Observe(time.Now().Sub(startTime).Seconds())
		return nil
	}
	return errors.New("Check Failed")
}

func checkLDAPConfigs(config AppConfigFile, rootCAs *x509.CertPool) {
	if len(config.Ldap.LDAPTargetURLs) > 0 {
		err := checkLDAPURLs(config.Ldap.LDAPTargetURLs, "passwd", rootCAs)
		if err != nil {
			logger.Debugf(1, "password LDAP check Failed %s", err)
		} else {
			lastSuccessLDAPPasswordTime = time.Now()
		}
		dependencyLastSuccessSecondsGauge.WithLabelValues("ldap", "passwd").
			Set(time.Now().Sub(lastSuccessLDAPPasswordTime).Seconds())
	}
	ldapConfig := config.UserInfo.Ldap
	if len(ldapConfig.LDAPTargetURLs) > 0 {
		err := checkLDAPURLs(ldapConfig.LDAPTargetURLs, "userinfo", rootCAs)
		if err != nil {
			logger.Debugf(1, "userinfo LDAP check Failed %s", err)
		} else {
			lastSuccessLDAPUserInfoTime = time.Now()
		}
		dependencyLastSuccessSecondsGauge.WithLabelValues("ldap", "userinfo").
			Set(time.Now().Sub(lastSuccessLDAPUserInfoTime).Seconds())
	}
}

func (state *RuntimeState) doDependencyMonitoring(secsBetweenChecks int) {
	for {
		checkLDAPConfigs(state.Config, nil)
		time.Sleep(time.Duration(secsBetweenChecks) * time.Second)
	}
}
