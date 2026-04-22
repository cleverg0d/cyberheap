package cli

import "github.com/spf13/cobra"

// Version is injected at build time via -ldflags. The default reflects
// the current source-tree version and is shown in the banner.
var Version = "0.1.2"

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "cyberheap",
		Short:         "CyberHeap - extract and triage secrets from Java HPROF heap dumps",
		Long:          "CyberHeap is a CLI for pentest engineers that parses Java heap dumps (HPROF)\nand extracts credentials, keys, tokens and other sensitive data.",
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(newInfoCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newBatchCmd())
	root.AddCommand(newStringsCmd())
	root.AddCommand(newDecryptCmd())
	return root
}
