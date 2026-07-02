package main

import (
	"fmt"
	"os"

	"github.com/fosrl/newt/authdaemon"
)

const (
	defaultPrincipalsPath = "/var/run/auth-daemon/principals"
	defaultCACertPath     = "/etc/ssh/ca.pem"
)

func runPrincipalsCmd(args []string) {
	opts := struct {
		PrincipalsFile string
		Username       string
	}{
		PrincipalsFile: defaultPrincipalsPath,
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--principals-file":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "Error: --principals-file requires a value\n")
				os.Exit(1)
			}
			opts.PrincipalsFile = args[i+1]
			i++
		case "--username":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "Error: --username requires a value\n")
				os.Exit(1)
			}
			opts.Username = args[i+1]
			i++
		case "--help", "-h":
			printPrincipalsHelp()
			os.Exit(0)
		default:
			fmt.Fprintf(os.Stderr, "Error: unknown flag: %s\n", args[i])
			printPrincipalsHelp()
			os.Exit(1)
		}
	}

	if opts.Username == "" {
		fmt.Fprintf(os.Stderr, "Error: username is required\n")
		printPrincipalsHelp()
		os.Exit(1)
	}

	list, err := authdaemon.GetPrincipals(opts.PrincipalsFile, opts.Username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if len(list) == 0 {
		fmt.Println("")
		return
	}
	for _, principal := range list {
		fmt.Println(principal)
	}
}

func printPrincipalsHelp() {
	fmt.Fprintf(os.Stderr, `Usage: newt principals [flags]

Output principals for a username (for AuthorizedPrincipalsCommand in sshd_config).
Read the principals file and print principals that match the given username, one per line.
Configure in sshd_config with AuthorizedPrincipalsCommand and %%u for the username.

Flags:
  --principals-file string   Path to the principals file (default "%s")
  --username string          Username to look up (required)
  --help, -h                 Show this help message

Example:
  newt principals --username alice

`, defaultPrincipalsPath)
}
