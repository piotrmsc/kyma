package v1alpha2

import (
	"regexp"
	"testing"
)

var hostnameCases = []struct {
	hostname string
	valid    bool
}{
	{"my-service", true},
	{"my-service.kyma.local", true},
	{"dot-is-escaped.kyma-local", false},
	{"with-subdomain.my-division", false},
	{"with-subdomain.my-division.kyma.local", false},
	{"wrong-domain.kima.locl", false},
	{"duplicated-domain.kyma.local.kyma.local", false},
	{"my-special-very-too-long-hostname-that-is-not-compliant-with-relevant-rfc", false},
	{"my-special-very-too-long-hostname-that-is-not-compliant-with-relevant-rfc.kyma.local", false},
}

func TestMatchHostname(t *testing.T) {
	re := regexp.MustCompile(hostnamePattern("kyma.local"))
	for _, tc := range hostnameCases {
		t.Run(tc.hostname, func(t *testing.T) {
			if re.MatchString(tc.hostname) != tc.valid {
				t.Errorf("Hostname '%s' should match: %v", tc.hostname, tc.valid)
			}
		})
	}
}

func TestIssuerPattern(t *testing.T) {
	issuers := []struct {
		iss   string
		valid bool
	}{
		{"justastringwithsome2#", false},
		{"http://dex.kyma.local", false},
		{"https://dex.kyma.local", true},
		{"user.sth@kyma-project.io", true},
		{"628645741881-noabiu23f5a8m8ovd8ucv698lj78vv0l@developer.gserviceaccount.com", true},
		{"https://accounts.google.com/.well-known/openid-configuration", true},
	}

	re := regexp.MustCompile(issuerPattern)
	for _, i := range issuers {
		t.Run(i.iss, func(t *testing.T) {
			if re.MatchString(i.iss) != i.valid {
				t.Errorf("Issuer '%s' should match but it didn't!", i.iss)
			}
		})
	}
}

func TestJWKSuriPattern(t *testing.T) {
	jwksURIs := []struct {
		uri   string
		valid bool
	}{
		{"https://www.googleapis.com/service_accounts/v1/jwk/628645741881-noabiu23f5a8m8ovd8ucv698lj78vv0l@developer.gserviceaccount.com", true},
		{"http://dex-service.kyma-system.svc.cluster.local:5556/keys", true},
		{"https://dex.kyma.local/keys", true},
		{"justastring@", false},
		{"user@kyma-project.io", false},
	}

	re := regexp.MustCompile(jwksURIPattern)
	for _, j := range jwksURIs {
		t.Run(j.uri, func(t *testing.T) {
			if re.MatchString(j.uri) != j.valid {
				t.Errorf("JWKS uri '%s' should match but it didn't!", j.uri)
			}
		})
	}
}
