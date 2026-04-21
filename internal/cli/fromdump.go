package cli

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/cleverg0d/cyberheap/internal/heap"
	"github.com/cleverg0d/cyberheap/internal/spiders"
)

// harvestShiroKeysFromDump parses an HPROF file, runs the shiro spider, and
// returns every cipher-key it finds as a list of base64 strings ready to feed
// into DecryptShiroCookie. Keys are pulled from:
//
//   - encryptionCipherKey  (post-2013 Shiro)
//   - decryptionCipherKey  (post-2013 Shiro, usually identical to above)
//   - cipherKey            (older Shiro releases)
//
// Duplicates are deduplicated so --from-dump doesn't produce redundant
// attempts against the cookie.
func harvestShiroKeysFromDump(path string) ([]string, error) {
	idx, err := openAndIndex(path)
	if err != nil {
		return nil, err
	}
	sp := shiroKeySpiderFindings(idx)
	seen := map[string]bool{}
	var out []string
	for _, f := range sp {
		for _, kv := range f.Fields {
			// The shiro spider publishes the key three ways per path:
			// base64, hex, and a length descriptor. We only need base64.
			if !strings.HasSuffix(kv.Name, "(base64)") {
				continue
			}
			if kv.Value == "" || seen[kv.Value] {
				continue
			}
			// Sanity: make sure it decodes to a valid AES key size.
			if !looksLikeAESKey(kv.Value) {
				continue
			}
			seen[kv.Value] = true
			out = append(out, kv.Value)
		}
	}
	return out, nil
}

// harvestJasyptPasswordsFromDump runs the jasypt spider and returns master
// password candidates extracted from StandardPBEStringEncryptor and similar
// encryptor instances living in the heap.
func harvestJasyptPasswordsFromDump(path string) ([]string, error) {
	idx, err := openAndIndex(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, sp := range spiders.Registry() {
		if sp.Name() != "jasypt" {
			continue
		}
		for _, f := range sp.Sniff(idx) {
			for _, kv := range f.Fields {
				if kv.Name != "password" || kv.Value == "" || seen[kv.Value] {
					continue
				}
				seen[kv.Value] = true
				out = append(out, kv.Value)
			}
		}
	}
	return out, nil
}

// openAndIndex reads an HPROF file fully and builds the searchable index.
// Centralized so we only pay the parse cost once per --from-dump call.
func openAndIndex(path string) (*heap.Index, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	idx, err := heap.Build(f)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return idx, nil
}

// shiroKeySpiderFindings runs only the shiro spider to minimize work when
// we're going to decrypt right after.
func shiroKeySpiderFindings(idx *heap.Index) []spiders.Finding {
	for _, sp := range spiders.Registry() {
		if sp.Name() == "shiro" {
			return sp.Sniff(idx)
		}
	}
	return nil
}

// looksLikeAESKey checks that base64 decodes to 16/24/32 bytes — valid AES
// key sizes. Filters out garbage that accidentally ended up shaped like a
// Shiro cipherKey field.
func looksLikeAESKey(b64 string) bool {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return false
	}
	n := len(raw)
	return n == 16 || n == 24 || n == 32
}

// Satisfy the compiler — we may want to surface hex forms later on.
var _ = hex.EncodeToString
