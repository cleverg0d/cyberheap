package scanner

import (
	"bytes"
	"regexp"
	"strings"
)

// commonTLDs is a conservative whitelist of top-level domains we accept
// as plausibly-real email. Using a whitelist (instead of blacklisting
// source-file extensions) kills the "Java package path" class of noise
// entirely — tokens like `httpclient`, `servlet`, `core`, `buf`,
// `loadbalancer`, `autoconfigure` simply aren't listed.
//
// Coverage: all major gTLDs + IANA-common ccTLDs for Europe, CIS, Asia,
// Middle East, Africa and the Americas. ~140 entries. Extend on demand.
var commonTLDs = map[string]bool{
	"com": true, "org": true, "net": true, "edu": true, "gov": true,
	"mil": true, "int": true, "info": true, "biz": true, "name": true,
	"mobi": true, "asia": true, "aero": true, "coop": true, "museum": true,
	"pro": true, "tel": true, "cat": true, "jobs": true,
	"io": true, "co": true, "me": true, "tv": true, "cc": true, "app": true,
	"dev": true, "tech": true, "xyz": true, "online": true, "site": true,
	"store": true, "shop": true, "email": true, "cloud": true, "ai": true,
	"page": true, "blog": true, "news": true, "today": true, "world": true,
	"club": true, "space": true, "life": true, "live": true, "one": true,
	"group": true, "company": true, "team": true, "agency": true, "studio": true,
	"de": true, "uk": true, "fr": true, "es": true, "it": true, "hu": true,
	"nl": true, "be": true, "se": true, "no": true, "dk": true, "fi": true,
	"pl": true, "cz": true, "sk": true, "at": true, "ch": true, "gr": true,
	"pt": true, "ie": true, "is": true, "lt": true, "lv": true, "ee": true,
	"ro": true, "bg": true, "hr": true, "si": true, "rs": true, "ba": true,
	"mk": true, "al": true, "cy": true, "mt": true, "lu": true, "li": true,
	"ru": true, "kz": true, "kg": true, "uz": true, "by": true, "ua": true,
	"az": true, "ge": true, "am": true, "tj": true, "tm": true, "md": true,
	"cn": true, "jp": true, "kr": true, "in": true, "sg": true, "my": true,
	"th": true, "vn": true, "id": true, "ph": true, "pk": true, "bd": true,
	"tr": true, "ir": true, "eg": true, "sa": true, "ae": true, "il": true,
	"ma": true, "za": true, "ng": true, "ke": true,
	"us": true, "ca": true, "mx": true, "br": true, "ar": true, "cl": true,
	"pe": true, "ve": true, "cu": true, "do": true, "py": true, "uy": true,
	"bo": true, "ec": true, "au": true, "nz": true, "eu": true,
}

// javaCACertEmails is the fixed set of CA contact addresses embedded in
// every JDK cacerts truststore. They're legitimate, they're just not
// worth surfacing — every heap dump containing the default truststore
// yields them. Silencing them keeps real signal visible.
var javaCACertEmails = map[string]bool{
	"pki@sk.ee":                       true,
	"chambersignroot@chambersign.org": true,
	"chambersroot@chambersign.org":    true,
	"accv@accv.es":                    true,
	"info@e-szigno.hu":                true,
	"info@izenpe.com":                 true,
	"ec_acc@catcert.net":              true,
	"ca@camerfirma.com":               true,
	"info@firmaprofesional.com":       true,
	"operations@digicert.com":         true,
	"postmaster@trustwave.com":        true,
}

// javaObjectRefRe matches Java's default Object.toString pattern:
// "ClassName@1f2497d9.FIELD" where the hex chunk is Integer.toHexString
// of the object's identity hash code.
var javaObjectRefRe = regexp.MustCompile(`@[0-9a-f]{6,12}\.`)

// isNonJWTBearer keeps bearer-token to non-JWT bearers only. JWT-shaped
// tokens (header.payload.signature, each base64) are handled by the
// more precise jwt-token pattern, which also renders decoded claims.
// Suppressing them here avoids showing the same token twice in different
// guises.
func isNonJWTBearer(value []byte) bool {
	return !bytes.Contains(value, []byte(".eyJ"))
}

// isBasicAuthLike rejects plain English words (e.g. "Authorization",
// "authentication") that syntactically look like base64 but are just the
// literal header names or code identifiers captured after "Basic ".
func isBasicAuthLike(value []byte) bool {
	hasAlphabetMix := false
	for _, c := range value {
		// Real base64 of "user:password" almost always contains a digit,
		// '+', '/' or padding '='. Pure alpha strings are false positives.
		if c == '=' || c == '+' || c == '/' || (c >= '0' && c <= '9') {
			hasAlphabetMix = true
			break
		}
	}
	return hasAlphabetMix
}

func isEmailLike(value []byte) bool {
	// Reject Java Object.toString() leaks — they syntactically look like
	// emails but the "@" is from hashCode formatting, not a domain separator.
	if javaObjectRefRe.Match(value) {
		return false
	}

	at := bytes.IndexByte(value, '@')
	if at < 0 || at == len(value)-1 {
		return false
	}
	localPart := value[:at]
	// URL-encoded garbage that accidentally matches — "%26" is `&`, "%3D"
	// is `=`, these come from URL query strings captured near "@mail.ru".
	if bytes.Contains(localPart, []byte("%")) {
		return false
	}

	dot := bytes.LastIndexByte(value, '.')
	if dot < 0 || dot == len(value)-1 {
		return false
	}
	tld := value[dot+1:]
	// Real TLDs are all-lowercase.
	for _, c := range tld {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	if !commonTLDs[string(tld)] {
		return false
	}

	// Drop known Java cacerts CA contact emails — not a leak, just noise
	// from the default truststore.
	if javaCACertEmails[strings.ToLower(string(value))] {
		return false
	}
	return true
}

// Printable ASCII range used in secret bodies. Heap memory is noisy, so we
// constrain matches to printable bytes to avoid capturing binary garbage.
const (
	printClass = `[\x20-\x7E]`
	identClass = `[A-Za-z0-9_.\-]`
)

// BuiltinPatterns returns the default pattern set. Ordered roughly by severity
// so pretty output shows the worst findings first when no explicit sort is
// requested.
func BuiltinPatterns() []*Pattern {
	return builtinPatterns
}

var builtinPatterns = []*Pattern{
	// ---------- CRITICAL ----------

	{
		Name:         "jdbc-url-with-password",
		Category:     CatDatasource,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`jdbc:[a-z0-9:+]+://[\x20-\x7E]{1,400}?password=([^&\s"'<>\x00]{1,200})`),
		captureGroup: 1,
		maxLen:       512,
	},
	{
		// Generic "password = ..." / "pwd: ..." / "passphrase=..."
		// Require the value to start with an alphanumeric and exclude
		// regex metacharacters and URL-query separators. Without `&;?`
		// in the negate class we'd pick up the entire tail of a URL
		// query ("password=foo&other=bar&..."); without `,|` we'd merge
		// CSV/log lines into one bogus value.
		Name:         "password-assignment",
		Category:     CatCredentials,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`(?i)(?:password|passwd|pwd|passphrase)\s*[=:]\s*["']?([A-Za-z0-9][^(){}\[\]\\\s"'<>\x00&;?,|]{3,127})`),
		captureGroup: 1,
		maxLen:       256,
	},
	{
		Name:     "rsa-private-key",
		Category: CatPrivateKey,
		// Private keys are unconditionally critical: possession = full
		// impersonation / decryption, no validation required.
		Severity: SeverityCritical,
		// Require the full PEM block (BEGIN + body + END). Header-only
		// matches would be false positives — they're Spring Security
		// error-message constants like "key must begin with -----BEGIN
		// PRIVATE KEY-----". Real keys stored in a Java String have
		// their bytes contiguous, so the strict regex catches them.
		re:           regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP |)PRIVATE KEY-----[A-Za-z0-9+/=\s]+?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP |)PRIVATE KEY-----`),
		captureGroup: 0,
		maxLen:       16384,
	},
	{
		Name:         "aws-secret-key-assignment",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})(?:["']|\b)`),
		captureGroup: 1,
		maxLen:       256,
	},
	{
		// Spring Boot common: spring.datasource.password=xxx
		Name:         "spring-datasource-password",
		Category:     CatDatasource,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`spring\.datasource(?:\.[a-z]+)*\.password\s*[=:]\s*["']?([^"'\s&<>\x00]{1,200})`),
		captureGroup: 1,
		maxLen:       256,
	},

	// ---------- HIGH ----------

	{
		Name:         "aws-access-key-id",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\b(AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b`),
		captureGroup: 0,
		maxLen:       32,
	},
	{
		Name:         "azure-storage-connection",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]{3,24};AccountKey=[A-Za-z0-9+/=]{64,}`),
		captureGroup: 0,
		maxLen:       1024,
	},
	{
		Name:         "google-service-account-private-key",
		Category:     CatCloud,
		Severity:     SeverityCritical,
		re:           regexp.MustCompile(`"type"\s*:\s*"service_account"`),
		captureGroup: 0,
		maxLen:       64,
	},
	{
		// OpenAI keys embed the fixed marker "T3BlbkFJ" (base64 of "OpenAI")
		// between two 20-char random halves. Using it collapses the false
		// positive rate from the naive sk- prefix.
		// Source: https://github.com/odomojuli/regextokens#openai
		Name:         "openai-key",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b`),
		captureGroup: 0,
		maxLen:       120,
	},
	{
		// Fine-grained PAT format introduced in 2022. Fixed-width, safe.
		// Source: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
		Name:         "github-fine-grained-pat",
		Category:     CatSCM,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b`),
		captureGroup: 0,
		maxLen:       120,
	},
	{
		Name:         "google-oauth-client-id",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\b[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com\b`),
		captureGroup: 0,
		maxLen:       128,
	},
	{
		// Google OAuth2 access token prefix.
		// Source: https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf
		Name:         "google-oauth-access-token",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bya29\.[A-Za-z0-9_\-]{40,200}\b`),
		captureGroup: 0,
		maxLen:       256,
	},
	{
		// Slack webhook URLs are unmistakable.
		// Source: https://api.slack.com/messaging/webhooks
		Name:         "slack-webhook-url",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bhttps://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{20,32}\b`),
		captureGroup: 0,
		maxLen:       160,
	},
	{
		// Mailchimp keys are hex + region tag.
		// Source: https://mailchimp.com/developer/marketing/guides/quick-start/
		Name:         "mailchimp-key",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\b[0-9a-f]{32}-us[0-9]{1,2}\b`),
		captureGroup: 0,
		maxLen:       40,
	},
	{
		// HashiCorp Vault tokens: s.* (service), b.* (batch).
		// Source: https://developer.hashicorp.com/vault/docs/concepts/tokens
		Name:         "vault-token",
		Category:     CatCredentials,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bhvs\.[A-Za-z0-9_\-]{20,100}\b`),
		captureGroup: 0,
		maxLen:       128,
	},
	{
		// Facebook long-lived Graph API tokens.
		// Source: regextokens + RegHex
		Name:         "facebook-access-token",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bEAACEdEose0cBA[0-9A-Za-z]{50,200}\b`),
		captureGroup: 0,
		maxLen:       256,
	},
	{
		// Cloudinary URL embeds API key + secret inline.
		// Source: RegHex
		Name:         "cloudinary-auth-url",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bcloudinary://[0-9]{15}:[A-Za-z0-9_\-]+@[a-z0-9][a-z0-9\-]{1,62}\b`),
		captureGroup: 0,
		maxLen:       160,
	},
	{
		// Amazon Marketplace Web Service auth token.
		// Source: regextokens + RegHex
		Name:         "aws-mws-key",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`),
		captureGroup: 0,
		maxLen:       64,
	},
	{
		// Square OAuth access tokens.
		// Source: https://developer.squareup.com/reference/square/oauth-api/obtaintoken
		Name:         "square-access-token",
		Category:     CatPaymentSaaS,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bsq0atp-[A-Za-z0-9_\-]{22}\b`),
		captureGroup: 0,
		maxLen:       48,
	},
	{
		// JFrog Artifactory API token (AKC prefix is official).
		// Source: RegHex
		Name:         "artifactory-api-token",
		Category:     CatCredentials,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bAKC[A-Za-z0-9]{50,90}\b`),
		captureGroup: 0,
		maxLen:       128,
	},
	{
		// Discord webhook URLs.
		Name:         "discord-webhook-url",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bhttps://discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,80}\b`),
		captureGroup: 0,
		maxLen:       200,
	},
	{
		// Telegram chat/channel invite links often leak admin access.
		Name:         "telegram-invite",
		Category:     CatCloud,
		Severity:     SeverityMedium,
		re:           regexp.MustCompile(`\bhttps://t\.me/(?:joinchat/|\+)[A-Za-z0-9_\-]{16,24}\b`),
		captureGroup: 0,
		maxLen:       80,
	},
	{
		// URL with embedded credentials: scheme://user:pass@host
		// Very common in JDBC URLs, git remotes, and FTP configs.
		// Capture the password portion for inline display.
		Name:         "url-embedded-auth",
		Category:     CatCredentials,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\b(?:https?|ftp|git|ssh|ldaps?|jdbc:[a-z]+)://[A-Za-z0-9_\-.%]{1,64}:([A-Za-z0-9_\-.!*+~%]{3,100})@[A-Za-z0-9][A-Za-z0-9.\-]{1,253}\b`),
		captureGroup: 1,
		maxLen:       256,
	},
	{
		Name:         "anthropic-key",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bsk-ant-(?:api03|sid01|admin01)-[A-Za-z0-9_\-]{90,120}\b`),
		captureGroup: 0,
		maxLen:       200,
	},
	{
		Name:         "huggingface-token",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,40}\b`),
		captureGroup: 0,
		maxLen:       64,
	},
	{
		Name:         "telegram-bot-token",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\b[0-9]{8,10}:[A-Za-z0-9_\-]{35}\b`),
		captureGroup: 0,
		maxLen:       64,
	},
	{
		Name:         "sendgrid-key",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`),
		captureGroup: 0,
		maxLen:       80,
	},
	{
		Name:         "mailgun-key",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bkey-[a-f0-9]{32}\b`),
		captureGroup: 0,
		maxLen:       48,
	},
	{
		Name:         "twilio-sid",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\b(?:SK|AC)[a-f0-9]{32}\b`),
		captureGroup: 0,
		maxLen:       48,
	},
	{
		Name:         "discord-bot-token",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\b[MN][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}\b`),
		captureGroup: 0,
		maxLen:       80,
	},
	{
		Name:         "npm-token",
		Category:     CatSCM,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
		captureGroup: 0,
		maxLen:       48,
	},
	{
		Name:         "github-token",
		Category:     CatSCM,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,251}\b`),
		captureGroup: 0,
		maxLen:       260,
	},
	{
		Name:         "gitlab-pat",
		Category:     CatSCM,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bglpat-[A-Za-z0-9\-_]{20,32}\b`),
		captureGroup: 0,
		maxLen:       64,
	},
	{
		Name:         "slack-token",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bxox[abprs]-[0-9A-Za-z\-]{10,64}\b`),
		captureGroup: 0,
		maxLen:       128,
	},
	{
		Name:         "stripe-key",
		Category:     CatPaymentSaaS,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\b(?:sk|pk|rk)_(?:test|live)_[A-Za-z0-9]{24,99}\b`),
		captureGroup: 0,
		maxLen:       128,
	},
	{
		Name:         "google-api-key",
		Category:     CatCloud,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
		captureGroup: 0,
		maxLen:       64,
	},
	{
		Name:         "jwt-token",
		Category:     CatJWT,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`),
		captureGroup: 0,
		maxLen:       2048,
	},
	{
		Name:         "bearer-token",
		Category:     CatAuth,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9_\-\.=+/]{16,500})`),
		captureGroup: 1,
		maxLen:       1024,
		postFilter:   isNonJWTBearer,
	},
	{
		// Jasypt-style encrypted values; the ciphertext itself is high value
		// because often paired with master password in heap.
		Name:         "jasypt-enc-value",
		Category:     CatCredentials,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`\bENC\(([A-Za-z0-9+/=]{16,200})\)`),
		captureGroup: 1,
		maxLen:       256,
	},
	{
		// Session cookies buffered inside HTTP response bodies, Spring
		// Session repos, or request wrappers still on the stack. Possession
		// of an active session ID is an immediate impersonation primitive.
		// 12+ alnum chars in the value to avoid doc-string false positives
		// like "JSESSIONID=HTTP session cookie".
		Name:         "session-cookie",
		Category:     CatCredentials,
		Severity:     SeverityHigh,
		re:           regexp.MustCompile(`(?i)(?:JSESSIONID|PHPSESSID|laravel_session|XSRF-TOKEN|CSRF-TOKEN|remember_me|SESSION|ASP\.NET_SessionId|connect\.sid)=([A-Za-z0-9+/=_\-]{12,256})`),
		captureGroup: 1,
		maxLen:       512,
	},

	// ---------- MEDIUM ----------

	{
		Name:         "basic-auth",
		Category:     CatAuth,
		Severity:     SeverityMedium,
		re:           regexp.MustCompile(`(?i)basic\s+([A-Za-z0-9+/=]{12,500})`),
		captureGroup: 1,
		maxLen:       512,
		postFilter:   isBasicAuthLike,
	},
	{
		// Require at least one alphanumeric host char after "://" to skip
		// schema literals in source code (e.g. "redis://" followed by backtick).
		Name:         "redis-url",
		Category:     CatConnString,
		Severity:     SeverityMedium,
		re:           regexp.MustCompile("rediss?://[A-Za-z0-9][^\\s<>\"'\\x00`]{3,299}"),
		captureGroup: 0,
		maxLen:       400,
	},
	{
		Name:         "mongo-url",
		Category:     CatConnString,
		Severity:     SeverityMedium,
		re:           regexp.MustCompile("mongodb(?:\\+srv)?://[A-Za-z0-9][^\\s<>\"'\\x00`]{3,399}"),
		captureGroup: 0,
		maxLen:       500,
	},
	{
		Name:         "amqp-url",
		Category:     CatConnString,
		Severity:     SeverityMedium,
		re:           regexp.MustCompile("amqps?://[A-Za-z0-9][^\\s<>\"'\\x00`]{3,299}"),
		captureGroup: 0,
		maxLen:       400,
	},
	{
		Name:         "smtp-url",
		Category:     CatConnString,
		Severity:     SeverityMedium,
		re:           regexp.MustCompile("smtps?://[A-Za-z0-9][^\\s<>\"'\\x00`]{3,299}"),
		captureGroup: 0,
		maxLen:       400,
	},
	{
		Name:         "ssh-public-key",
		Category:     CatPrivateKey,
		Severity:     SeverityMedium,
		re:           regexp.MustCompile(`\bssh-(?:rsa|ed25519|dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)\s+[A-Za-z0-9+/=]{68,}`),
		captureGroup: 0,
		maxLen:       1024,
	},

	// ---------- LOW / INFO ----------

	{
		// At least 3 chars in the local part. `%` is excluded because
		// real addresses almost never contain it — seeing it means we
		// grabbed part of a URL-encoded query. TLD must be one of our
		// whitelisted common domains; Java package paths ("jersey",
		// "autoconfigure", "loadbalancer") never appear there.
		Name:         "email-address",
		Category:     CatPersonal,
		Severity:     SeverityLow,
		re:           regexp.MustCompile(`\b[A-Za-z0-9][A-Za-z0-9._+\-]{2,63}@[A-Za-z0-9][A-Za-z0-9.\-]{1,253}\.[a-z]{2,24}\b`),
		captureGroup: 0,
		maxLen:       320,
		postFilter:   isEmailLike,
	},
	// Note: a generic "internal hostname" pattern was tried here but produced
	// massive noise from JDK class names (jdk.internal.*, sun.nio.*, etc.).
	// It will return in Phase 2 once we can scope detection to actual string
	// objects in the heap rather than raw package paths.
}
