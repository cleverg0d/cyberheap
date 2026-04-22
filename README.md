# CyberHeap

**Fast triage of Java heap dumps for pentesters.** Extract credentials, API
keys, tokens and private keys out of HPROF files in seconds — no JVM
required, no Eclipse MAT, no manual string grepping.

```
 ____ _   _ ___  ____ ____ _  _ ____ ____ ___
|     \_/  |__] |___ |__/ |__| |___ |__| |__]
|___   |   |__] |___ |  \ |  | |___ |  | |
        HPROF secret scanner · by clevergod
```

CyberHeap combines two complementary passes over the dump:

1. **Regex scan** — runs ~40 tuned patterns (AWS / GCP / Azure / GitHub /
   GitLab / Slack / Stripe / OpenAI / Anthropic / HuggingFace / Telegram /
   SendGrid / Mailgun / Twilio / Discord / JWT / basic auth / JDBC URLs
   / private keys / emails and more) across the raw bytes.
2. **Structured scan** — parses the HPROF format, indexes every class and
   instance, and pulls credentials directly out of Java objects (Spring
   `DataSourceProperties`, Hikari, Druid, Mongo, Apache Shiro, …) even when
   the cleartext isn't near any recognisable marker.

Recognised tokens are **decoded inline** (basic-auth shows `user:password`,
JWTs show their `iss`/`sub`/`exp`/`scope` claims) so triage is a one-step
read instead of a copy-paste-decode loop.

---

## Features

- Single statically-linked Go binary. No JVM, no runtime deps.
- Scans local files **or** remote URLs (e.g. `https://target/actuator/heapdump`).
- Severity-bucketed output: **CRITICAL / HIGH / MEDIUM / LOW / INFO**.
- Inline decoding of base64 basic-auth credentials and JWT claims.
- Smart masking for client reports — domain of an email stays visible,
  password body is starred, JWT header is kept so the algorithm is readable.
- Persistent JSON reports (`-o DIR`) with merge-on-rerun semantics, tracking
  first/last seen per finding for retests.
- Class-aware structured findings carry the Java FQN and heap object ID so
  each reported password is traceable to its origin in the dump.
- Pretty terminal output with aligned columns and framed banner; `--no-color`
  for scripts and `--format=json` for pipelines.

---

## Install

### Build from source

Requires Go 1.22+.

```sh
git clone https://github.com/cleverg0d/cyberheap.git
cd cyberheap
make build
./bin/cyberheap --help
```

The binary lands at `./bin/cyberheap`. Copy it anywhere on your `$PATH`.

### Cross-compile

```sh
GOOS=linux   GOARCH=amd64 go build -o cyberheap-linux-amd64  ./cmd/cyberheap
GOOS=linux   GOARCH=arm64 go build -o cyberheap-linux-arm64  ./cmd/cyberheap
GOOS=darwin  GOARCH=arm64 go build -o cyberheap-darwin-arm64 ./cmd/cyberheap
GOOS=windows GOARCH=amd64 go build -o cyberheap-windows.exe  ./cmd/cyberheap
```

---

## Commands

### `scan` — find secrets in a dump

```sh
cyberheap scan <file.hprof | http(s)://host/path/heapdump>
```

Runs both regex and structured passes by default and merges the findings.

| Flag | Purpose |
|------|---------|
| `--severity a,b,c` | Filter by severity: `critical,high,medium,low,info` |
| `--category a,b`   | Filter by category: `datasource,cloud,scm,jwt,auth,credentials,connection-string,private-key,payment-saas,personal,shiro` |
| `--mask`           | Mask secret values (for client-facing evidence) |
| `-v, --verbose`    | Show byte offsets and the raw encoded value for decoded findings |
| `--max-value N`    | Truncate raw values longer than N chars (0 = unlimited) |
| `--min-count N`    | Drop findings seen fewer than N times in the dump |
| `--utf16`          | Also scan a squeezed view for UTF-16LE strings (JDK 8 `char[]`) |
| `--no-regex`       | Skip the regex pass (structured pass only — ~1 s on a 100 MiB dump) |
| `--no-spiders`     | Skip the structured pass (regex only) |
| `--no-header-check`| Scan any file as raw bytes (for corrupted or non-standard dumps) |
| `-o, --output DIR` | Save/merge findings as JSON into `DIR/<target>.json` |
| `--format f`       | `pretty` (default), `json`, or `markdown` |
| `--patterns FILE`  | Load extra regex rules from a gitleaks-compatible TOML file (repeatable) |
| `--patterns-only`  | Use ONLY `--patterns` files, skip the built-in catalogue |
| `--diff-against FILE` | Compare against a saved JSON report — tag findings `+` / `=` / `-` |
| `--no-color`       | Disable ANSI colors |
| `--no-banner`      | Suppress the banner |

Auto-selected paths (no flag needed):

- **regex pass** streams in 64 MiB chunks with 16 KiB overlap when the dump is ≥ 512 MiB.
- **structured pass** mmap's the file zero-copy when the dump is ≥ 256 MiB local.
- Both fall back to the in-memory path on smaller dumps or remote URLs.

### `info` — inspect dump metadata

```sh
cyberheap info <file.hprof>                  # header only (instant)
cyberheap info <file.hprof> --deep           # parse everything + class stats
cyberheap info <file.hprof> --deep --top=30  # top N populated classes
cyberheap info <file.hprof> --json           # machine-readable
```

`--deep` parses the full dump and reports:

- HPROF version, ID size, timestamp, header length
- String table size, class count, instance count, sub-record count
- Per-tag record breakdown (`STRING_IN_UTF8`, `LOAD_CLASS`, …)
- Top N classes by instance count (useful for fingerprinting the stack)

### `batch` — scan many dumps, get one summary

```sh
cyberheap batch dumps/*.hprof -o ./reports --severity=critical,high
```

Each dump is scanned independently; per-file JSON reports land in `-o DIR`.
Stdout shows a compact "filename → counts" table and aggregate totals
across all files.

Useful flags:

- `--fail-on-critical` — exit non-zero on any CRITICAL (CI-friendly)
- `--mask`, `--utf16`, `--no-regex`, `--no-spiders`, `--severity`, `--category` — same semantics as `scan`

### `scan --diff-against` — retest deltas

```sh
cyberheap scan dump-v1.hprof -o ./reports             # baseline
cyberheap scan dump-v2.hprof --diff-against=./reports/dump-v1.json
```

Each finding in the new scan is prefixed:

- `+` — new since the baseline
- `=` — unchanged (same pattern + value, or same spider/class/object)
- `-` — closed (was in baseline, gone now — shown in a dedicated
  "CLOSED since previous scan" block)

Exactly what you want driving a retest against an earlier evidence pack.

### `decrypt` — offline decryption of common enterprise ciphers

```sh
# Jasypt — ENC(...) strings from application.properties
cyberheap decrypt jasypt --password=MASTER --value='ENC(...)'
cyberheap decrypt jasypt --auto --try-password=A --try-password=B --value='ENC(...)'
cyberheap decrypt jasypt --from-dump=./heap.hprof --value='ENC(...)'   # harvest master from heap

# Shiro RememberMe cookies
cyberheap decrypt shiro --key=<base64-16> --cookie=<base64> --mode=cbc
cyberheap decrypt shiro --auto --cookie=<base64>               # tries well-known defaults
cyberheap decrypt shiro --auto --cookie=<base64> --try-key=<base64>
cyberheap decrypt shiro --from-dump=./heap.hprof --cookie=<base64>     # harvest key from heap

# JWT decode + optional HMAC verify
cyberheap decrypt jwt   --token=<jwt>                           # just decode
cyberheap decrypt jwt   --token=<jwt> --secret=<HMAC-secret>    # decode + verify
cyberheap decrypt jwt   --auto --token=<jwt> --try-secret=A --try-secret=B
```

Supported:

- **Jasypt** — nine profiles covering Jasypt 1.x (PBKDF1-MD5/SHA1 with DES / 3DES) and Jasypt 3.x (PBKDF2 + AES). Full list:
  `PBEWithMD5AndDES`, `PBEWithMD5AndTripleDES`, `PBEWithSHA1AndDESede`,
  `PBEWithHMACSHA1AndAES_128/256`, `PBEWithHMACSHA256AndAES_128/256`,
  `PBEWithHMACSHA512AndAES_128/256` (Jasypt 3.x default).
- **Shiro RememberMe** — AES-128/192/256 in both CBC (Shiro ≤ 1.2.4, CVE-2016-4437) and GCM (newer Shiro). `--auto` tries every hard-coded default key shipped with the vulnerable releases plus any extras the `shiro` spider harvested from the heap.
- **JWT** — full verification for HS256/384/512 (HMAC), RS256/384/512
  (RSA-PKCS1v15), PS256/384/512 (RSA-PSS), ES256/384/512 (ECDSA over
  P-256/P-384/P-521), and EdDSA (Ed25519). Public keys come from PEM
  files (`--public-key FILE`) or inline PEM blobs (`--public-key-pem`).
  The `alg:none` attack is always rejected. Claims are returned even
  when the signature fails, which mirrors the triage flow.

All subcommands accept `--json` for machine-readable output.

### `strings` — dump Java-resolvable strings

```sh
cyberheap strings FILE                            # every resolved java.lang.String + STRING_IN_UTF8
cyberheap strings FILE --grep=password --unique   # case-insensitive filter + dedup
cyberheap strings FILE --regex='(?i)api[_-]?key'  # Go regex filter
cyberheap strings FILE --include=utf8             # only intern'd constants
cyberheap strings FILE --include=instances        # only runtime java.lang.String
cyberheap strings FILE --ascii --min-length=8     # printable ASCII, ≥ 8 chars
cyberheap strings FILE --sort=freq --unique       # top-used strings first
cyberheap strings FILE --scan                     # run the secret catalogue ONLY over resolved strings
                                                  # (cleaner signal than `scan`, no binary noise)
```

`--scan` is a pentest power move: the regex catalogue runs against the
real string objects instead of raw heap bytes, so every match is a
concrete Java string — no partial byte matches, no accidental hits on
serialized blobs.

---

## Examples

### Quick scan of a local file

> All sample values below are synthetic — placeholder credentials for
> illustration purposes, not real secrets.

```sh
$ cyberheap scan ./example-heapdump
╔════════════════════════════════════════════════════╗
║    ____ _   _ ___  ____ ____ _  _ ____ ____ ___    ║
║   |     \_/  |__] |___ |__/ |__| |___ |__| |__]    ║
║   |___   |   |__] |___ |  \ |  | |___ |  | |       ║
║                                                    ║
║  v0.1.1  ·  HPROF secret scanner  ·  by clevergod  ║
╚════════════════════════════════════════════════════╝

  file        ./example-heapdump
  format      HPROF 1.0.2   size 120.0 MiB   id-size 8 bytes   header 31 bytes
  timestamp   2026-01-15 10:00:00 UTC
  elapsed     3.0s
  summary     6 findings (regex 3 + structured 3)   ● 2 CRITICAL   ● 1 HIGH   ● 2 MEDIUM   ● 1 LOW   ● 0 INFO

───────────────────────────────────── HIGH ─────────────────────────────────────

  jwt-token:      iss=https://auth.example.com/realms/demo sub=user-0001 exp=2026-02-01 12:00:00Z

──────────────────────────────────── MEDIUM ────────────────────────────────────

  basic-auth:     demo-client:demo-secret
  basic-auth:     svc-account:ExamplePass-01 (x3)

───────────────────────────────────── LOW ──────────────────────────────────────

  email-address:  user@example.com (x2)

━━━━━━━━━━━━━━━━━━━━━━━━━━━ STRUCTURED (class-aware) ━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [CRITICAL] Spring DataSourceProperties
      class: org.springframework.boot.autoconfigure.jdbc.DataSourceProperties   object: 0xabcdef01
      driverClassName         org.postgresql.Driver
      url                     jdbc:postgresql://db.internal/demo
      username                demo_app
      password                ExamplePassword-01

  [HIGH] Spring PropertySource: applicationConfig: [classpath:/application.yml]
      class: org.springframework.boot.env.OriginTrackedMapPropertySource   object: 0xabcdef02
      app.jwt.secret          ExampleJwtSecret-01
      spring.datasource.password  ExamplePassword-01
```

### Scan a live target over HTTP

```sh
cyberheap scan https://target.example.com/actuator/heapdump -o ./reports
```

The dump is streamed to a temp file, scanned, then deleted. The filename of
the saved report is derived from the hostname (`target.example.com.json`).

### Generate a masked report for a client

```sh
cyberheap scan ./heapdump --mask -o ./client-reports/ --format=pretty > report.txt
```

Emails keep their domain, passwords are starred, JWT headers remain readable
so the algorithm (`HS256`, `RS256`) is documented in the finding.

### Re-scan after remediation

```sh
cyberheap scan ./heapdump-after-fix -o ./reports
# saved ./reports/heapdump-after-fix.json  (+0 new, 8 updated, 3 closed)
```

Findings are merged by `(pattern, value)` for regex hits and
`(spider, class, object_id)` for structured hits. Each record tracks
`first_seen` / `last_seen` / `runs` so you can diff retests.

### Structured pass only (fast credential hunt)

```sh
cyberheap scan ./heapdump --no-regex --severity=critical,high
```

On a 100 MiB dump this runs in ~700 ms and surfaces DataSource/Shiro
credentials without the regex noise.

### Custom regex rules (gitleaks-compat TOML)

Drop a rules file into the engagement directory, load it alongside the
built-in catalogue, and tighten it with an allowlist:

```toml
# custom-rules.toml
[[rules]]
id          = "acme-internal-token"
description = "Acme internal service token"
regex       = '''\bacme_tok_[A-Za-z0-9]{32}\b'''
severity    = "CRITICAL"
category    = "credentials"

[[rules]]
id       = "acme-cloud-key"
regex    = '''\bAKEY-[A-Z0-9]{20}\b'''
severity = "HIGH"

[rules.allowlist]
regexes   = ['''EXAMPLE''', '''DEMO''']
stopwords = ["fake", "placeholder"]
```

```sh
cyberheap scan ./heapdump --patterns=./custom-rules.toml
cyberheap scan ./heapdump --patterns=./custom-rules.toml --patterns-only
```

`keywords`, `entropy`, and `allowlist.paths` from gitleaks are parsed
but reported as warnings — CyberHeap doesn't need them (RE2 is fast
enough; paths aren't a dimension of heap data).

---

## Real-world validation: CVE-2016-4437 (Apache Shiro deserialization)

End-to-end walk-through against the public
[vulhub/shiro/CVE-2016-4437](https://github.com/vulhub/vulhub/tree/master/shiro/CVE-2016-4437)
lab. This is the canonical Shiro `rememberMe` RCE — a baked-in default
AES key on Shiro ≤ 1.2.4 lets an attacker forge a serialized Java object
inside the cookie and trigger deserialization gadgets on the server.

### 1. Start the vulnerable app and capture a heap dump

```sh
git clone --depth 1 https://github.com/vulhub/vulhub /tmp/vulhub
cd /tmp/vulhub/shiro/CVE-2016-4437
docker compose up -d

# The image ships JRE only — use jattach (single static binary) for the dump.
curl -fsSL https://github.com/jattach/jattach/releases/download/v2.2/jattach-linux-x64.tgz \
  | tar xz -C /tmp
docker cp /tmp/jattach cve-2016-4437-web-1:/tmp/jattach
docker exec cve-2016-4437-web-1 \
  sh -c '/tmp/jattach $(pgrep -f java) dumpheap /tmp/shiro.hprof'
docker cp cve-2016-4437-web-1:/tmp/shiro.hprof ./shiro-ctf.hprof
```

### 2. Scan — cipher key falls out in ~1.4 s

```sh
$ cyberheap scan ./shiro-ctf.hprof --no-regex
  summary  1 findings (regex 0 + structured 1)   ● 1 CRITICAL

━━━━━━━━━━━━━━━━━━━━━━━━━━━ STRUCTURED (class-aware) ━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [CRITICAL] Shiro RememberMe cipher key (RCE primitive)
      class: org.apache.shiro.web.mgt.CookieRememberMeManager   object: 0x85fdfd70
      encryptionCipherKey (base64)  kPH+bIxk5D2deZiIxcaaaA==
      encryptionCipherKey (hex)     90f1fe6c8c64e43d9d799888c5c69a68
      encryptionCipherKey (bytes)   16 (AES-128)
      algorithm                     AES
```

That base64 is the historical default key for every Shiro ≤ 1.2.4 install.
CyberHeap ships it in the well-known-keys list as well, so even an empty
heap dump would allow auto-recovery when paired with a live cookie.

### 3. Decrypt a captured rememberMe cookie in one command

Grab the cookie from a valid login (browser or curl), then:

```sh
$ cyberheap decrypt shiro \
    --from-dump=./shiro-ctf.hprof \
    --cookie='jTFMjfyULCJ8kT4u0xvz...long-base64...Lsn0w=='

  harvested 1 Shiro cipher-key(s) from ./shiro-ctf.hprof
  mode:           CBC
  key:            kPH+bIxk5D2deZiIxcaaaA==
  length:         377 bytes
  java-serialized: true
  hex preview:    aced000573720032 6f72672e6170616368652e736869726f2e7375626a6563742e53696d706c655072696e636970616c436f6c6c656374696f6e ...
```

- `aced 0005` — Java `ObjectOutputStream` magic. The payload really is a
  deserialized object, exactly the primitive CVE-2016-4437 relies on.
- Classname `org.apache.shiro.subject.SimplePrincipalCollection` — this
  is the admin session principal, confirming the decryption matched.

The same `--from-dump` flag works for `decrypt jasypt` against Jasypt
master-password candidates harvested by the `jasypt` spider, so
`ENC(...)` values in `application.properties` can be reversed without
the analyst ever copy-pasting the master password.

Total time from `docker compose up` to serialized payload in hand: **~10
seconds**. This used to be a 15-30 minute manual chain (locate the key in
Shiro sources, decode and split IV, run a Java one-liner) — CyberHeap
collapses it to two commands.

## Output formats

### `pretty` (default)

Human-readable, ANSI-coloured, grouped by severity. The `STRUCTURED` section
at the bottom carries class/object context for each class-aware finding.

### `json`

Single JSON object with separate `findings` (regex) and `structured_findings`
(spider) arrays. Consume it with `jq`:

```sh
cyberheap scan ./heapdump --format=json | jq '.findings[] | select(.severity=="CRITICAL")'
```

### `markdown`

GitHub-flavoured Markdown assessment report with severity summary table,
per-pattern findings table, per-class structured tables, and CWE
references — suitable to paste into a client deliverable:

```sh
cyberheap scan ./heapdump --format=markdown --mask > report.md
```

Under `--mask` all secret values are obfuscated while the class/key names
stay readable, making the output safe to share.

### Persisted reports (`-o DIR`)

Pretty output to stdout **and** a merge-aware JSON report on disk. Each run
updates the report with new findings, keeps per-finding `first_seen`/`last_seen`
timestamps and a `runs` counter. Ideal for driving retests and evidence
packs.

---

## What gets detected

### Regex patterns (~40)

Credentials and assignment syntaxes:
- JDBC URLs with inline passwords
- `password = ...`, `pwd: ...`, `passphrase = ...`
- Spring Boot `spring.datasource.password=`
- RSA / EC / OPENSSH / ENCRYPTED / PGP private key headers
- URL-embedded credentials (`scheme://user:pass@host`)
- Jasypt `ENC(...)` values

Cloud providers:
- AWS access key IDs, secret keys, MWS tokens
- Azure storage connection strings
- Google OAuth client IDs, access tokens, API keys
- Google service-account JSON markers

SCM and SaaS:
- GitHub classic + fine-grained PATs, OAuth tokens
- GitLab PATs, npm tokens
- Slack bot/user/webhook tokens, Discord webhook URLs, Telegram invites
- Stripe keys, Square tokens, Artifactory API tokens

AI and messaging:
- OpenAI keys (with the `T3BlbkFJ` internal marker)
- Anthropic keys (`sk-ant-*`)
- HuggingFace, SendGrid, Mailgun, Twilio, Cloudinary

Session and transport:
- Basic auth and Bearer tokens (with JWT claim decoding)
- JWTs with compact claim summary
- Redis, Mongo, AMQP, SMTP URLs
- HashiCorp Vault tokens

Personal / contextual:
- Email addresses (with Java stack trace noise filtered out)

### Structured (class-aware) spiders

- **datasource** — Spring `DataSourceProperties`, Hikari (`HikariConfig`,
  `HikariDataSource`), Druid, Apache DBCP2, Tomcat JDBC, Weblogic, MongoDB
  `MongoClientURI` and `ConnectionString`.
- **shiro** — `CookieRememberMeManager` and `AbstractRememberMeManager`
  (with all subclasses), extracts `cipherKey`, `encryptionCipherKey`,
  `decryptionCipherKey` plus the cipher algorithm name. The key is
  reported as base64, hex, and byte length for direct hand-off to
  `cyberheap decrypt shiro`.
- **propertysource** — Spring `MapPropertySource`, `OriginTrackedMapPropertySource`,
  `PropertiesPropertySource`, `SystemEnvironmentPropertySource` and their
  subclasses. Walks the internal `HashMap` / `LinkedHashMap` /
  `ConcurrentHashMap` / `Hashtable` / `Properties` / `SingletonMap` /
  `UnmodifiableMap` backing store and surfaces every key whose name
  matches a secret-carrying pattern (`password`, `clientsecret`,
  `accesskey`, `jwt.secret`, …).
- **redis** — Spring Data Redis (`RedisStandaloneConfiguration`,
  `RedisSentinelConfiguration`, `RedisClusterConfiguration`), Jedis
  (`JedisShardInfo`), Lettuce (`RedisURI` with `char[]` password).
- **env** — JVM process environment (`java.lang.ProcessEnvironment`
  static fields). Filters by secret-shaped keys, drops trivial values
  (paths, booleans, bare integers) to avoid noise.
- **jasypt** — `StandardPBEStringEncryptor`, `PooledPBEStringEncryptor`,
  configuration classes and Spring Boot wrappers. Extracts the master
  password (char[] / byte[] / String) so `decrypt jasypt --auto` can
  unlock every `ENC(...)` string in the dump.
- **cloudcreds** — AWS SDK v1 & v2 (`BasicAWSCredentials`,
  `AwsBasicCredentials`, session variants), Aliyun OSS & Core SDK
  credential classes, Alibaba credentials-java, Huawei OBS, Tencent
  COS. Returns `accessKey` + `secretKey` + optional `sessionToken`.

A finding is only reported when genuine credential evidence is present
(a non-null password, or a URL with a scheme). Findings are deduplicated
across target classes so inheritance hierarchies (e.g. `HikariDataSource`
extending `HikariConfig`) don't double-report the same object.

---

## HPROF compatibility

- Format 1.0.1 and 1.0.2
- 4-byte and 8-byte identifiers (auto-detected from the header)
- JDK 8 `java.lang.String` (`char[] value`) and JDK 9+ (`byte[] value` +
  `coder` for LATIN1 / UTF-16LE)
- Modified UTF-8 decoding for `STRING_IN_UTF8` records
- `HEAP_DUMP` and `HEAP_DUMP_SEGMENT` containers
- Sub-records: `CLASS_DUMP`, `INSTANCE_DUMP`, `OBJECT_ARRAY_DUMP`,
  `PRIMITIVE_ARRAY_DUMP`, all `ROOT_*` variants
- Dotted field paths with automatic traversal of object references

---

## Limitations

- On actively-running pools, some Hikari pool objects null out their
  password field after `pool.start()`. The real credential is kept in
  the corresponding `DataSourceProperties` object, which CyberHeap
  reports correctly; the dedup logic prevents double-counting.
- HPROF 1.0.0 (pre-Java 5) is not supported. All modern JVMs emit 1.0.1
  or 1.0.2.
- The structured pass currently keeps the index in RAM. On the mmap
  path (≥ 256 MiB files) the OS pages only what we touch, so peak
  working set stays well below the dump size — but an exhaustive walk
  of a multi-GiB dump still burns GiB of RAM. Suitable for every
  heap-dump size we've encountered in real pentest engagements.

---

## Ethics

CyberHeap is intended for **authorised** penetration tests, red team
engagements, bug bounty programs, and incident response on systems you own
or have explicit permission to test. Using it against third-party systems
without authorisation is illegal in most jurisdictions.

Exposed `/actuator/heapdump` endpoints are a well-documented class of
misconfiguration; CyberHeap automates triage once access is legitimate.

---

## Prior art

CyberHeap's class-aware extraction model is inspired by
[JDumpSpider](https://github.com/whwlsfb/JDumpSpider) (Apache 2.0). The
HPROF parser and spider framework are written from scratch in Go with a
significantly expanded set of targets, inline decoders, severity modelling,
masking and persistence layers.

---

## License

MIT — see [LICENSE](./LICENSE).

---

## Author

[@cleverg0d](https://github.com/cleverg0d) · [@securixy_kz](https://t.me/securixy_kz)
