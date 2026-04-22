package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is injected at build time via -ldflags. The default reflects
// the current source-tree version and is shown in the banner.
var Version = "0.1.5"

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "cyberheap",
		Short: "CyberHeap v" + Version + " - triage Java HPROF heap dumps for pentest",
		Long: "CyberHeap v" + Version + "\n\n" +
			"Extract credentials, API keys, tokens and private keys from Java\n" +
			"HPROF heap dumps. Validate them live. Discover exposed Spring Boot\n" +
			"actuator endpoints with a single command.\n\n" +
			"Quick start:\n" +
			"  cyberheap scan heap.hprof                 # local dump\n" +
			"  cyberheap scan https://host/actuator/heapdump\n" +
			"  cyberheap recon https://host              # find actuators + auto-scan\n" +
			"  cyberheap info heap.hprof --deep          # dump metadata + class stats\n" +
			"  cyberheap decrypt jwt --token <JWT>       # offline decode / verify",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	// Manual --version handling so the conventional -V shorthand works
	// (matches nuclei, netexec, curl, ssh-audit, ...). Cobra's auto
	// Version field claims -v, which collides with --verbose on
	// subcommands.
	var showVersion bool
	root.Flags().BoolVarP(&showVersion, "version", "V", false, "show version and exit")
	root.RunE = func(cmd *cobra.Command, args []string) error {
		if showVersion {
			fmt.Fprintf(cmd.OutOrStdout(), "cyberheap version %s\n", Version)
			return nil
		}
		return cmd.Help()
	}
	root.AddCommand(newInfoCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newBatchCmd())
	root.AddCommand(newStringsCmd())
	root.AddCommand(newDecryptCmd())
	root.AddCommand(newReconCmd())
	return root
}
