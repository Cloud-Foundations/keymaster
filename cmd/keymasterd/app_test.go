package main

import (
	"regexp"
	"testing"
)

type oktaUsernameFilterTestType struct {
	filter string
	input  string
	output string
}

var (
	oktaUsernameFilterTests = []oktaUsernameFilterTestType{
		{"", "user", "user"},
		{"", "user@company.com", "user@company.com"},
		{"", "user@company.com@blah", "user@company.com@blah"},
		{defaultOktaUsernameFilterRegexp, "user", "user"},
		{defaultOktaUsernameFilterRegexp, "user@company.com", "user"},
		{defaultOktaUsernameFilterRegexp, "user@company.com@blah", "user"},
	}
)

func TestOktaUsernameFilter(t *testing.T) {
	state := &RuntimeState{}
	for _, testCase := range oktaUsernameFilterTests {
		state.oktaUsernameFilterRE = regexp.MustCompile(testCase.filter)
		output := state.reprocessUsername(testCase.input)
		if output != testCase.output {
			t.Errorf(
				"filter: \"%s\", input: \"%s\", output!=expected: \"%s\" != \"%s\"",
				testCase.filter, testCase.input, output, testCase.output)
		}
	}
}
