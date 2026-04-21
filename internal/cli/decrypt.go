package cli

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cleverg0d/cyberheap/internal/decrypt"
)

// newDecryptCmd wires `cyberheap decrypt {jasypt,shiro,jwt}`.
func newDecryptCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt Jasypt strings, Shiro RememberMe cookies, verify JWTs",
		Long: `Local, offline decryption primitives that pair with CyberHeap's
class-aware findings. For each subcommand an --auto mode probes
well-known defaults and any candidates you've harvested from a heap.`,
	}
	root.AddCommand(newDecryptJasyptCmd())
	root.AddCommand(newDecryptShiroCmd())
	root.AddCommand(newDecryptJWTCmd())
	return root
}

// --- jasypt ---------------------------------------------------------------

type jasyptFlags struct {
	password string
	value    string
	algo     string
	auto     bool
	extraPW  []string
	fromDump string
	asJSON   bool
}

func newDecryptJasyptCmd() *cobra.Command {
	var f jasyptFlags
	cmd := &cobra.Command{
		Use:   "jasypt",
		Short: "Decrypt a Jasypt-encrypted string (ENC(...) or raw base64)",
		Long: `Recover the plaintext behind Jasypt's StandardPBEStringEncryptor or
PooledPBEStringEncryptor output. Supported algorithms are the ones
Jasypt 1.x ships by default: PBEWithMD5AndDES, PBEWithMD5AndTripleDES,
PBEWithSHA1AndDESede.

Examples:

  cyberheap decrypt jasypt --password=master --value='ENC(ABCD...)'
  cyberheap decrypt jasypt --value='ENC(ABCD...)' --auto \
      --try-password=candidate1 --try-password=candidate2`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runJasypt(cmd, &f)
		},
	}
	cmd.Flags().StringVar(&f.password, "password", "", "master password (required unless --auto is set)")
	cmd.Flags().StringVar(&f.value, "value", "", "encrypted value (ENC(...) or raw base64)")
	cmd.Flags().StringVar(&f.algo, "algo", "", "algorithm (default: PBEWithMD5AndDES)")
	cmd.Flags().BoolVar(&f.auto, "auto", false, "try every algorithm against --try-password candidates")
	cmd.Flags().StringArrayVar(&f.extraPW, "try-password", nil, "additional candidate master password (repeatable)")
	cmd.Flags().StringVar(&f.fromDump, "from-dump", "", "parse this HPROF file and harvest Jasypt master passwords from encryptor instances (implies --auto)")
	cmd.Flags().BoolVar(&f.asJSON, "json", false, "emit JSON result")
	_ = cmd.MarkFlagRequired("value")
	return cmd
}

func runJasypt(cmd *cobra.Command, f *jasyptFlags) error {
	w := cmd.OutOrStdout()

	// --from-dump automatically selects --auto mode: harvesting only makes
	// sense when we're about to cycle through candidates.
	if f.fromDump != "" {
		f.auto = true
		harvested, err := harvestJasyptPasswordsFromDump(f.fromDump)
		if err != nil {
			return fmt.Errorf("--from-dump: %w", err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "  harvested %d Jasypt master-password candidate(s) from %s\n",
			len(harvested), f.fromDump)
		f.extraPW = append(f.extraPW, harvested...)
	}

	if f.auto {
		candidates := append([]string{}, f.extraPW...)
		if f.password != "" {
			candidates = append(candidates, f.password)
		}
		if len(candidates) == 0 {
			return fmt.Errorf("--auto needs at least one candidate (via --password, --try-password, or --from-dump)")
		}
		pt, used, algo, ok := decrypt.TryJasyptAuto(f.value, candidates)
		if !ok {
			if f.asJSON {
				return json.NewEncoder(w).Encode(map[string]any{"ok": false})
			}
			fmt.Fprintln(w, "  no candidate decrypted cleanly")
			return fmt.Errorf("no match")
		}
		if f.asJSON {
			return json.NewEncoder(w).Encode(map[string]any{
				"ok":        true,
				"plaintext": pt,
				"password":  used,
				"algo":      algo,
			})
		}
		fmt.Fprintf(w, "  algo:       %s\n", algo)
		fmt.Fprintf(w, "  password:   %s\n", used)
		fmt.Fprintf(w, "  plaintext:  %s\n", pt)
		return nil
	}

	if f.password == "" {
		return fmt.Errorf("--password is required (or use --auto with --try-password)")
	}
	pt, err := decrypt.DecryptJasypt(f.password, f.value, f.algo)
	if err != nil {
		return err
	}
	if f.asJSON {
		return json.NewEncoder(w).Encode(map[string]any{
			"ok":        true,
			"plaintext": pt,
			"algo":      f.algo,
		})
	}
	fmt.Fprintln(w, pt)
	return nil
}

// --- shiro ----------------------------------------------------------------

type shiroFlags struct {
	key      string
	cookie   string
	mode     string
	auto     bool
	extraKey []string
	fromDump string
	asJSON   bool
}

func newDecryptShiroCmd() *cobra.Command {
	var f shiroFlags
	cmd := &cobra.Command{
		Use:   "shiro",
		Short: "Decrypt an Apache Shiro RememberMe cookie (AES-CBC / AES-GCM)",
		Long: `Recover the Java-serialized payload from a Shiro RememberMe cookie.
Pass --auto to cycle through well-known default keys plus any extras
supplied via --try-key (typically harvested from a heap dump with the
shiro spider).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runShiro(cmd, &f)
		},
	}
	cmd.Flags().StringVar(&f.key, "key", "", "base64 cipher key (16/24/32 bytes raw)")
	cmd.Flags().StringVar(&f.cookie, "cookie", "", "RememberMe cookie value (base64)")
	cmd.Flags().StringVar(&f.mode, "mode", "cbc", "cipher mode: cbc | gcm")
	cmd.Flags().BoolVar(&f.auto, "auto", false, "try well-known defaults + --try-key candidates")
	cmd.Flags().StringArrayVar(&f.extraKey, "try-key", nil, "extra candidate key (repeatable)")
	cmd.Flags().StringVar(&f.fromDump, "from-dump", "", "parse this HPROF file and harvest Shiro cipher keys from CookieRememberMeManager instances (implies --auto)")
	cmd.Flags().BoolVar(&f.asJSON, "json", false, "emit JSON result")
	_ = cmd.MarkFlagRequired("cookie")
	return cmd
}

func runShiro(cmd *cobra.Command, f *shiroFlags) error {
	w := cmd.OutOrStdout()

	if f.fromDump != "" {
		f.auto = true
		harvested, err := harvestShiroKeysFromDump(f.fromDump)
		if err != nil {
			return fmt.Errorf("--from-dump: %w", err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "  harvested %d Shiro cipher-key(s) from %s\n",
			len(harvested), f.fromDump)
		f.extraKey = append(f.extraKey, harvested...)
	}

	if f.auto {
		pt, used, mode, ok := decrypt.TryShiroAuto(f.cookie, f.extraKey)
		if !ok {
			if f.asJSON {
				return json.NewEncoder(w).Encode(map[string]any{"ok": false})
			}
			fmt.Fprintln(w, "  no candidate decrypted cleanly")
			return fmt.Errorf("no match")
		}
		return printShiroResult(w, pt, used, modeString(mode), f.asJSON)
	}

	var m decrypt.ShiroCipherMode
	switch strings.ToLower(f.mode) {
	case "cbc":
		m = decrypt.ShiroCBC
	case "gcm":
		m = decrypt.ShiroGCM
	default:
		return fmt.Errorf("unknown mode %q (cbc or gcm)", f.mode)
	}
	if f.key == "" {
		return fmt.Errorf("--key is required (or use --auto)")
	}
	pt, err := decrypt.DecryptShiroCookie(f.key, f.cookie, m)
	if err != nil {
		return err
	}
	return printShiroResult(w, pt, f.key, f.mode, f.asJSON)
}

func printShiroResult(w io.Writer, pt []byte, key, mode string, asJSON bool) error {
	isJava := decrypt.LooksLikeJavaSerialized(pt)
	if asJSON {
		return json.NewEncoder(w).Encode(map[string]any{
			"ok":                    true,
			"mode":                  mode,
			"key":                   key,
			"plaintext_hex":         hex.EncodeToString(pt),
			"plaintext_base64":      base64.StdEncoding.EncodeToString(pt),
			"looks_java_serialized": isJava,
		})
	}
	fmt.Fprintf(w, "  mode:           %s\n", strings.ToUpper(mode))
	fmt.Fprintf(w, "  key:            %s\n", key)
	fmt.Fprintf(w, "  length:         %d bytes\n", len(pt))
	fmt.Fprintf(w, "  java-serialized: %t\n", isJava)
	previewLen := 64
	if len(pt) < previewLen {
		previewLen = len(pt)
	}
	fmt.Fprintf(w, "  hex preview:    %s\n", hex.EncodeToString(pt[:previewLen]))
	if isJava {
		fmt.Fprintln(w, "  note:           payload is a Java serialized object — deserializing it")
		fmt.Fprintln(w, "                  on the target is the RCE primitive. Do NOT hand it back to")
		fmt.Fprintln(w, "                  an attacker-controlled process without sandboxing.")
	}
	return nil
}

func modeString(m decrypt.ShiroCipherMode) string {
	switch m {
	case decrypt.ShiroCBC:
		return "cbc"
	case decrypt.ShiroGCM:
		return "gcm"
	}
	return "?"
}

// --- jwt ------------------------------------------------------------------

type jwtFlags struct {
	token         string
	secret        string
	publicKeyFile string
	publicKeyPEM  string
	auto          bool
	extraKey      []string
	asJSON        bool
	claimOnly     bool
}

func newDecryptJWTCmd() *cobra.Command {
	var f jwtFlags
	cmd := &cobra.Command{
		Use:   "jwt",
		Short: "Decode and optionally verify an HS256/384/512 JWT",
		Long: `Decode the header and claims, and (if --secret or --auto is given)
verify the HMAC signature. Claims are always returned, even when the
signature fails — this mirrors the triage workflow where you get a
token from a dump and want to read it regardless of whether you hold
the signing key.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runJWT(cmd, &f)
		},
	}
	cmd.Flags().StringVar(&f.token, "token", "", "JWT string (three base64-url parts separated by '.')")
	cmd.Flags().StringVar(&f.secret, "secret", "", "HMAC signing secret (UTF-8) — for HS256/384/512")
	cmd.Flags().StringVar(&f.publicKeyFile, "public-key", "", "path to PEM-encoded RSA/ECDSA/Ed25519 public key — for RS/PS/ES/EdDSA")
	cmd.Flags().StringVar(&f.publicKeyPEM, "public-key-pem", "", "inline PEM-encoded public key (alternative to --public-key)")
	cmd.Flags().BoolVar(&f.auto, "auto", false, "brute-force HMAC candidates from --secret + --try-secret (HS* only)")
	cmd.Flags().StringArrayVar(&f.extraKey, "try-secret", nil, "extra candidate HMAC secret (repeatable)")
	cmd.Flags().BoolVar(&f.asJSON, "json", false, "emit JSON result")
	cmd.Flags().BoolVar(&f.claimOnly, "claims-only", false, "print only the claims JSON, nothing else")
	_ = cmd.MarkFlagRequired("token")
	return cmd
}

func runJWT(cmd *cobra.Command, f *jwtFlags) error {
	w := cmd.OutOrStdout()

	// Auto brute-force: HMAC only. Asymmetric algorithms can't be
	// brute-forced (public key is, well, public), so --auto implies HS*.
	if f.auto {
		candidates := append([]string{}, f.extraKey...)
		if f.secret != "" {
			candidates = append(candidates, f.secret)
		}
		res, used, ok := decrypt.TryJWTAuto(f.token, candidates)
		return printJWT(w, res, used, ok, f)
	}

	// Decide which key form to pass to VerifyJWT.
	var key any
	switch {
	case f.publicKeyFile != "":
		data, err := os.ReadFile(f.publicKeyFile)
		if err != nil {
			return fmt.Errorf("read public key file: %w", err)
		}
		key, err = decrypt.ParsePublicKey(data)
		if err != nil {
			return fmt.Errorf("parse public key: %w", err)
		}
	case f.publicKeyPEM != "":
		var err error
		key, err = decrypt.ParsePublicKey([]byte(f.publicKeyPEM))
		if err != nil {
			return fmt.Errorf("parse --public-key-pem: %w", err)
		}
	case f.secret != "":
		key = f.secret
	default:
		key = nil // decode only
	}

	res, err := decrypt.VerifyJWT(f.token, key)
	if err != nil {
		return err
	}
	usedLabel := ""
	if f.publicKeyFile != "" {
		usedLabel = f.publicKeyFile
	} else if f.publicKeyPEM != "" {
		usedLabel = "<inline PEM>"
	} else {
		usedLabel = f.secret
	}
	return printJWT(w, res, usedLabel, res.SignatureValid, f)
}

func printJWT(w io.Writer, res *decrypt.JWTResult, used string, ok bool, f *jwtFlags) error {
	if f.claimOnly {
		return json.NewEncoder(w).Encode(res.Claims)
	}
	if f.asJSON {
		return json.NewEncoder(w).Encode(map[string]any{
			"alg":              res.Alg,
			"signature_valid":  res.SignatureValid,
			"mismatch":         res.Mismatch,
			"matched_secret":   used,
			"auto_match_found": ok,
			"header":           res.Header,
			"claims":           res.Claims,
		})
	}
	fmt.Fprintf(w, "  alg:        %s\n", res.Alg)
	fmt.Fprintf(w, "  verified:   %t\n", res.SignatureValid)
	if res.SignatureValid && used != "" {
		fmt.Fprintf(w, "  secret:     %s\n", used)
	}
	if res.Mismatch != "" {
		fmt.Fprintf(w, "  note:       %s\n", res.Mismatch)
	}
	fmt.Fprintln(w, "  claims:")
	cj, _ := json.MarshalIndent(res.Claims, "              ", "  ")
	fmt.Fprintf(w, "              %s\n", string(cj))
	if !ok {
		os.Stderr.WriteString("")
	}
	return nil
}
