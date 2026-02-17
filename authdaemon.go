package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/fosrl/newt/authdaemon"
	"github.com/fosrl/newt/logger"
)

const (
	defaultPrincipalsPath = "/var/run/auth-daemon/principals"
	defaultCACertPath     = "/etc/ssh/ca.pem"
)

var (
	errPresharedKeyRequired = errors.New("auth-daemon-key is required when --auth-daemon is enabled")
	errRootRequired         = errors.New("auth-daemon must be run as root (use sudo)")
	authDaemonServer        *authdaemon.Server // Global auth daemon server instance
)

// startAuthDaemon initializes and starts the auth daemon in the background.
// It validates requirements (Linux, root, preshared key) and starts the server
// in a goroutine so it runs alongside normal newt operation.
func startAuthDaemon(ctx context.Context) error {
	// Validation
	if runtime.GOOS != "linux" {
		return fmt.Errorf("auth-daemon is only supported on Linux, not %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return errRootRequired
	}

	// Use defaults if not set
	principalsFile := authDaemonPrincipalsFile
	if principalsFile == "" {
		principalsFile = defaultPrincipalsPath
	}
	caCertPath := authDaemonCACertPath
	if caCertPath == "" {
		caCertPath = defaultCACertPath
	}

	// Create auth daemon server
	cfg := authdaemon.Config{
		DisableHTTPS:       true, // We run without HTTP server in newt
		PresharedKey:       "this-key-is-not-used",   // Not used in embedded mode, but set to non-empty to satisfy validation
		PrincipalsFilePath: principalsFile,
		CACertPath:         caCertPath,
		Force:              true,
	}

	srv, err := authdaemon.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("create auth daemon server: %w", err)
	}

	authDaemonServer = srv

	// Start the auth daemon in a goroutine so it runs alongside newt
	go func() {
		logger.Info("Auth daemon starting (native mode, no HTTP server)")
		if err := srv.Run(ctx); err != nil {
			logger.Error("Auth daemon error: %v", err)
		}
		logger.Info("Auth daemon stopped")
	}()

	return nil
}



// runPrincipalsCmd executes the principals subcommand logic
func runPrincipalsCmd(args []string) {
	opts := struct {
		PrincipalsFile string
		Username       string
	}{
		PrincipalsFile: defaultPrincipalsPath,
	}

	// Parse flags manually
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

	// Validation
	if opts.Username == "" {
		fmt.Fprintf(os.Stderr, "Error: username is required\n")
		printPrincipalsHelp()
		os.Exit(1)
	}

	// Get principals
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