package dbsc_test

import (
	"fmt"
	"testing"

	"github.com/movitz-s/dbsc-go"
)

func TestRegistrationHeader(t *testing.T) {

	testEntries := []struct {
		input    dbsc.SessionRegistrationConfig
		expected string
	}{
		{
			input: dbsc.SessionRegistrationConfig{
				SupportedAlgorithms: []string{dbsc.AlgES256},
				Path:                "/startSession",
				Challenge:           "challenge123",
			},
			expected: `(ES256);challenge="challenge123";path="/startSession"`,
		},
		{
			input: dbsc.SessionRegistrationConfig{
				SupportedAlgorithms: []string{dbsc.AlgES256, dbsc.AlgRS256},
				Path:                "a",
				Challenge:           "xyz",
				Authorization:       "testauth",
			},
			expected: `(ES256 RS256);challenge="xyz";path="a";authorization="testauth"`,
		},
	}

	for _, entry := range testEntries {

		output := dbsc.RegistrationHeader(entry.input)

		if output != entry.expected {
			t.Fail()
			fmt.Println("expected", entry.expected)
			fmt.Println("output", output)
		}
	}

}
