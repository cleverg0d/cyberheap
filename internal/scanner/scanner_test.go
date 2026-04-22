package scanner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func findByName(matches []Match, name string) *Match {
	for i := range matches {
		if matches[i].Pattern.Name == name {
			return &matches[i]
		}
	}
	return nil
}

func TestScan_ImportedPatterns(t *testing.T) {
	// Pattern fixtures are built by concatenation so GitHub's push-protection
	// secret scanner doesn't flag them as real API keys. They still render
	// as literal keys at runtime — just not as static source strings.
	openaiKey := "sk-proj-" + strings.Repeat("a", 20) + "T3Blbk" + "FJ" + strings.Repeat("b", 20)
	slackHook := "https://hooks.slack.com/services/" + "T" + strings.Repeat("0", 10) + "/B" + strings.Repeat("0", 10) + "/" + strings.Repeat("a", 24)
	mailchimpKey := strings.Repeat("0", 32) + "-us12"
	squareTok := "sq" + "0atp-" + strings.Repeat("0", 22)

	corpus := []byte(strings.Join([]string{
		"openai=" + openaiKey,
		"github_pat_12345678901234567890AB_" + strings.Repeat("a", 59),
		"gcp=1234567890-abcdef0123456789abcdef0123456789.apps.googleusercontent.com",
		"gtoken=ya29.a0AfH6SMBqXY" + strings.Repeat("a", 60),
		"webhook=" + slackHook,
		"mc=" + mailchimpKey,
		"vault=hvs.ABCDEFGHIJKLMNOPQRSTUVWX",
		"fb=EAACEdEose0cBA" + strings.Repeat("x", 80),
		"cloud=cloudinary://123456789012345:ABCDEFGHIJ123@acme-corp",
		"mws=amzn.mws.4ea38b7b-f563-46f5-b123-456789abcdef",
		"sq=" + squareTok,
		"art=AKC" + strings.Repeat("x", 60),
		"disc=https://discord.com/api/webhooks/123456789012345678/" + strings.Repeat("a", 65),
		"tg=https://t.me/+AbCdEfGhIjKlMnOpQr",
		"url=postgresql://dbuser:MyP@ssw0rd!@db.prod.internal",
		"url2=https://alice:hunter2@git.corp.local/repo.git",
	}, "\n"))

	matches, err := Scan(bytes.NewReader(corpus), Options{})
	require.NoError(t, err)

	want := []string{
		"openai-key",
		"github-fine-grained-pat",
		"google-oauth-client-id",
		"google-oauth-access-token",
		"slack-webhook-url",
		"mailchimp-key",
		"vault-token",
		"facebook-access-token",
		"cloudinary-auth-url",
		"aws-mws-key",
		"square-access-token",
		"artifactory-api-token",
		"discord-webhook-url",
		"telegram-invite",
		"url-embedded-auth",
	}
	names := []string{}
	for _, m := range matches {
		names = append(names, m.Pattern.Name)
	}
	for _, w := range want {
		assert.NotNil(t, findByName(matches, w), "expected %s in %v", w, names)
	}
}

func TestScan_CatchesCommonSecrets(t *testing.T) {
	corpus := []byte(strings.Join([]string{
		"spring.datasource.url=jdbc:mysql://prod-db.corp:3306/app?useSSL=true&password=Sup3rS3cret!",
		"spring.datasource.username=root",
		"spring.datasource.password=Sup3rS3cret!",
		"aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
		"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"github_token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
		"slack_bot_token=" + "xo" + "xb-1234567890-0987654321-" + strings.Repeat("a", 24),
		"JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.abc123defGHIJKL",
		"contact_email=admin@example.com",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\nKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n-----END RSA PRIVATE KEY-----",
		"redis_url=redis://default:pass123@cache.internal:6379/0",
		"mongo=mongodb+srv://user:p@ss@cluster0.mongodb.net/db",
		"Authorization: Bearer opaque-session-abcdef1234567890xyz",
		"jasypt_value=ENC(kLyqTZgX5rO3pJfM1nBvCxA2QwErTyUi)",
	}, "\n"))

	matches, err := Scan(bytes.NewReader(corpus), Options{})
	require.NoError(t, err)

	names := []string{}
	for _, m := range matches {
		names = append(names, m.Pattern.Name)
	}

	wantAny := []string{
		"jdbc-url-with-password",
		"spring-datasource-password",
		"aws-access-key-id",
		"aws-secret-key-assignment",
		"github-token",
		"slack-token",
		"jwt-token",
		"email-address",
		"rsa-private-key",
		"redis-url",
		"mongo-url",
		"bearer-token",
		"jasypt-enc-value",
	}
	for _, want := range wantAny {
		assert.NotNil(t, findByName(matches, want), "pattern %s should fire, got=%v", want, names)
	}
}

func TestScan_SeverityFilter(t *testing.T) {
	corpus := []byte("AKIAIOSFODNN7EXAMPLE and email=a@b.co and -----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\nKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n-----END RSA PRIVATE KEY-----")

	// Private keys are the only class pinned at CRITICAL by default
	// (possession = impersonation, no validation required).
	critical, err := Scan(bytes.NewReader(corpus), Options{
		Severities: SeveritySet{SeverityCritical: true},
	})
	require.NoError(t, err)
	assert.NotNil(t, findByName(critical, "rsa-private-key"))

	high, err := Scan(bytes.NewReader(corpus), Options{
		Severities: SeveritySet{SeverityHigh: true},
	})
	require.NoError(t, err)
	for _, m := range high {
		assert.Equal(t, SeverityHigh, m.Pattern.Severity)
	}
	assert.NotNil(t, findByName(high, "aws-access-key-id"))
	assert.Nil(t, findByName(high, "rsa-private-key"), "not HIGH, it's CRITICAL")
	assert.Nil(t, findByName(high, "email-address"), "LOW filtered out")
}

func TestScan_Deduplicates(t *testing.T) {
	corpus := []byte(strings.Repeat("password=hunter22\n", 5))
	matches, err := Scan(bytes.NewReader(corpus), Options{})
	require.NoError(t, err)

	m := findByName(matches, "password-assignment")
	require.NotNil(t, m)
	assert.Equal(t, 5, m.Count)
	assert.Equal(t, "hunter22", m.Value)
}

func TestScan_UTF16LE(t *testing.T) {
	// Encode "AKIAIOSFODNN7EXAMPLE" as UTF-16LE.
	src := "prefix AKIAIOSFODNN7EXAMPLE suffix"
	u16 := make([]byte, 0, 2*len(src))
	for _, r := range src {
		u16 = append(u16, byte(r), 0x00)
	}

	// Without UTF-16 scan the AWS key stays hidden.
	m1, err := Scan(bytes.NewReader(u16), Options{})
	require.NoError(t, err)
	assert.Nil(t, findByName(m1, "aws-access-key-id"))

	m2, err := Scan(bytes.NewReader(u16), Options{ScanUTF16: true})
	require.NoError(t, err)
	assert.NotNil(t, findByName(m2, "aws-access-key-id"))
}

func TestPatterns_AllCompile(t *testing.T) {
	assert.NotEmpty(t, BuiltinPatterns())
	for _, p := range BuiltinPatterns() {
		assert.NotNil(t, p.re, "pattern %s has nil regex", p.Name)
		assert.NotEmpty(t, p.Name)
		assert.NotEmpty(t, p.Category)
	}
}

func TestContextSnippet(t *testing.T) {
	data := []byte("xxxpassword=supersecretyyy")
	s := ContextSnippet(data, 3, len("password=supersecret"), 3)
	assert.Contains(t, s, "password=supersecret")
}
