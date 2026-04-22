package spiders

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestURLEmbeddedAuthRe covers the regex that promotes a property value
// like Eureka's defaultZone=http://user:pass@host/eureka into a
// secret-prefix seed regardless of the key's name. Positive cases must
// match; plain URLs without creds must not.
func TestURLEmbeddedAuthRe(t *testing.T) {
	positive := []string{
		"http://admin:s3cret@eureka.internal/eureka/",
		"https://user:pass@api.example.com",
		"jdbc:mysql://dbuser:dbpass@db.internal/app",
		"ftp://backup:hunter2@ftp.internal/",
		"amqp://rabbit:password@queue.internal:5672",
	}
	for _, v := range positive {
		assert.True(t, urlEmbeddedAuthRe.MatchString(v), "should match: %q", v)
	}
	negative := []string{
		"",
		"http://example.com/path",
		"https://api.example.com:443",
		"jdbc:postgresql://db/app",
		"user:pass@host", // no scheme
		"http:///no-host",
		"arbitrary text without url",
	}
	for _, v := range negative {
		assert.False(t, urlEmbeddedAuthRe.MatchString(v), "should NOT match: %q", v)
	}
}

// TestLooksCompanionKey_Eureka asserts the Spring Cloud discovery keys
// are recognised as companions so they surface alongside a secret prefix.
func TestLooksCompanionKey_Eureka(t *testing.T) {
	companion := []string{
		"eureka.client.serviceUrl.defaultZone",
		"eureka.client.service-url.defaultZone",
		"eureka.client.register-with-eureka",
		"eureka.client.fetch-registry",
		"spring.cloud.discovery.serviceUrl",
	}
	for _, k := range companion {
		assert.True(t, looksCompanionKey(k), "expected companion: %q", k)
	}
	notCompanion := []string{
		"eureka.instance.appname",
		"spring.application.name",
		"logging.level.root",
	}
	for _, k := range notCompanion {
		assert.False(t, looksCompanionKey(k), "unexpected companion: %q", k)
	}
}
