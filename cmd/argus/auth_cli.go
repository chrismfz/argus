package main

// auth_cli.go — user & session management embedded in the argus binary.
//
// Usage:
//   argus auth user add -u chris -r admin
//   argus auth user list
//   argus auth user passwd -u chris
//   argus auth user roles -u chris -r admin,viewer
//   argus auth user deactivate -u chris
//   argus auth user activate -u chris
//   argus auth user delete -u chris --force
//   argus auth session list
//   argus auth session purge
//
// The --db flag defaults to /opt/argus/etc/auth.db so it rarely needs
// to be specified explicitly on watchdog.
//
// This pattern (embedding a management CLI inside the service binary) is
// documented in the goauth README as the recommended approach for
// single-binary deployments.

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/chrismfz/goauth"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const defaultAuthDB = "/opt/argus/etc/auth.db"

// runAuthCLI is called from main() when os.Args[1] == "auth".
// It never returns — it calls os.Exit via cobra.
func runAuthCLI() {
	var dbPath string

	root := &cobra.Command{
		Use:   "argus auth",
		Short: "Manage Argus users and sessions",
		Long: `Manage users and sessions for the Argus NOC.

All commands operate directly on the SQLite auth database.
The Argus server does not need to be running.

Examples:
  argus auth user add -u chris -r admin
  argus auth user list
  argus auth session purge`,
		// Don't show usage on every error — just the error message.
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVar(
		&dbPath, "db", defaultAuthDB,
		"Path to the auth SQLite database",
	)

	userCmd := &cobra.Command{
		Use:   "user",
		Short: "Manage user accounts",
	}
	userCmd.AddCommand(
		authCmdUserAdd(&dbPath),
		authCmdUserList(&dbPath),
		authCmdUserInfo(&dbPath),
		authCmdUserPasswd(&dbPath),
		authCmdUserRoles(&dbPath),
		authCmdUserActivate(&dbPath),
		authCmdUserDeactivate(&dbPath),
		authCmdUserDelete(&dbPath),
	)

	sessionCmd := &cobra.Command{
		Use:   "session",
		Short: "Manage active sessions",
	}
	sessionCmd.AddCommand(
		authCmdSessionList(&dbPath),
		authCmdSessionPurge(&dbPath),
	)

	root.AddCommand(userCmd, sessionCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func authOpen(dbPath *string) (*goauth.Manager, error) {
	m, err := goauth.New(goauth.Config{
		DBPath:       *dbPath,
		SessionTTL:   8 * time.Hour,
		SecureCookie: false, // irrelevant for CLI use
	})
	if err != nil {
		return nil, fmt.Errorf("cannot open auth database %q: %w\n"+
			"  Hint: make sure the directory exists and argus has write access.", *dbPath, err)
	}
	return m, nil
}

// authPromptPassword reads a password from the terminal without echoing it.
// Falls back to plain stdin read if not running in a terminal.
func authPromptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(syscall.Stdin)) {
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr) // newline after hidden input
		return string(b), err
	}
	// Non-interactive (piped input) — plain read.
	var pw string
	_, err := fmt.Scanln(&pw)
	return pw, err
}

// ── user add ──────────────────────────────────────────────────────────────────

func authCmdUserAdd(dbPath *string) *cobra.Command {
	var username, password string
	var roles []string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Create a new user",
		Example: `  argus auth user add -u chris -r admin
  argus auth user add -u readonly -r viewer`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if password == "" {
				var err error
				password, err = authPromptPassword("Password: ")
				if err != nil {
					return err
				}
				confirm, err := authPromptPassword("Confirm password: ")
				if err != nil {
					return err
				}
				if password != confirm {
					return fmt.Errorf("passwords do not match")
				}
			}

			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()

			if err := m.Users.Create(username, password, roles); err != nil {
				return err
			}
			fmt.Printf("✓ User %q created", username)
			if len(roles) > 0 {
				fmt.Printf(" with roles: [%s]", strings.Join(roles, ", "))
			}
			fmt.Println()
			return nil
		},
	}

	cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Password (prompted securely if omitted)")
	cmd.Flags().StringSliceVarP(&roles, "roles", "r", []string{}, "Comma-separated roles, e.g. admin,viewer")
	cmd.MarkFlagRequired("username")
	return cmd
}

// ── user list ─────────────────────────────────────────────────────────────────

func authCmdUserList(dbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all users",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()

			users, err := m.Users.List()
			if err != nil {
				return err
			}
			if len(users) == 0 {
				fmt.Println("No users found.")
				return nil
			}

			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "ID\tUSERNAME\tROLES\tACTIVE\tCREATED")
			fmt.Fprintln(tw, "--\t--------\t-----\t------\t-------")
			for _, u := range users {
				active := "yes"
				if !u.Active {
					active = "no"
				}
				fmt.Fprintf(tw, "%d\t%s\t[%s]\t%s\t%s\n",
					u.ID,
					u.Username,
					strings.Join(u.Roles, ", "),
					active,
					u.CreatedAt.Format("2006-01-02 15:04"),
				)
			}
			tw.Flush()
			return nil
		},
	}
}

// ── user info ─────────────────────────────────────────────────────────────────

func authCmdUserInfo(dbPath *string) *cobra.Command {
	var username string

	cmd := &cobra.Command{
		Use:   "info",
		Short: "Show detailed info for a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()

			u, err := m.Users.GetByUsername(username)
			if err != nil {
				return err
			}

			active := "yes"
			if !u.Active {
				active = "no (disabled)"
			}

			fmt.Printf("ID:       %d\n", u.ID)
			fmt.Printf("Username: %s\n", u.Username)
			fmt.Printf("Roles:    [%s]\n", strings.Join(u.Roles, ", "))
			fmt.Printf("Active:   %s\n", active)
			fmt.Printf("Created:  %s\n", u.CreatedAt.Format(time.RFC3339))
			fmt.Printf("Updated:  %s\n", u.UpdatedAt.Format(time.RFC3339))
			return nil
		},
	}

	cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	cmd.MarkFlagRequired("username")
	return cmd
}

// ── user passwd ───────────────────────────────────────────────────────────────

func authCmdUserPasswd(dbPath *string) *cobra.Command {
	var username, password string

	cmd := &cobra.Command{
		Use:   "passwd",
		Short: "Change a user's password",
		RunE: func(cmd *cobra.Command, args []string) error {
			if password == "" {
				var err error
				password, err = authPromptPassword("New password: ")
				if err != nil {
					return err
				}
				confirm, err := authPromptPassword("Confirm new password: ")
				if err != nil {
					return err
				}
				if password != confirm {
					return fmt.Errorf("passwords do not match")
				}
			}

			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()

			if err := m.Users.SetPassword(username, password); err != nil {
				return err
			}
			fmt.Printf("✓ Password updated for %q\n", username)
			return nil
		},
	}

	cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "New password (prompted securely if omitted)")
	cmd.MarkFlagRequired("username")
	return cmd
}

// ── user roles ────────────────────────────────────────────────────────────────

func authCmdUserRoles(dbPath *string) *cobra.Command {
	var username string
	var roles []string

	cmd := &cobra.Command{
		Use:     "roles",
		Short:   "Replace the role list for a user",
		Example: `  argus auth user roles -u chris -r admin,viewer`,
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()

			if err := m.Users.SetRoles(username, roles); err != nil {
				return err
			}
			fmt.Printf("✓ Roles for %q set to [%s]\n", username, strings.Join(roles, ", "))
			return nil
		},
	}

	cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	cmd.Flags().StringSliceVarP(&roles, "roles", "r", nil, "New role list, replaces existing (required)")
	cmd.MarkFlagRequired("username")
	cmd.MarkFlagRequired("roles")
	return cmd
}

// ── user activate / deactivate ────────────────────────────────────────────────

func authCmdUserActivate(dbPath *string) *cobra.Command {
	var username string

	cmd := &cobra.Command{
		Use:   "activate",
		Short: "Re-enable a disabled user account",
		RunE: func(cmd *cobra.Command, args []string) error {
			return authSetActive(dbPath, username, true)
		},
	}
	cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	cmd.MarkFlagRequired("username")
	return cmd
}

func authCmdUserDeactivate(dbPath *string) *cobra.Command {
	var username string

	cmd := &cobra.Command{
		Use:   "deactivate",
		Short: "Disable a user account without deleting it",
		RunE: func(cmd *cobra.Command, args []string) error {
			return authSetActive(dbPath, username, false)
		},
	}
	cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	cmd.MarkFlagRequired("username")
	return cmd
}

func authSetActive(dbPath *string, username string, active bool) error {
	m, err := authOpen(dbPath)
	if err != nil {
		return err
	}
	defer m.Close()

	if err := m.Users.SetActive(username, active); err != nil {
		return err
	}
	state := "activated"
	if !active {
		state = "deactivated"
	}
	fmt.Printf("✓ User %q %s\n", username, state)
	return nil
}

// ── user delete ───────────────────────────────────────────────────────────────

func authCmdUserDelete(dbPath *string) *cobra.Command {
	var username string
	var force bool

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Permanently delete a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				fmt.Printf("This will permanently delete %q. Pass --force to confirm.\n", username)
				return nil
			}

			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()

			if err := m.Users.Delete(username); err != nil {
				return err
			}
			fmt.Printf("✓ User %q deleted\n", username)
			return nil
		},
	}

	cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	cmd.Flags().BoolVar(&force, "force", false, "Required confirmation flag")
	cmd.MarkFlagRequired("username")
	return cmd
}

// ── session list ──────────────────────────────────────────────────────────────

func authCmdSessionList(dbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List active (non-expired) sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()

			sessions, err := m.ListSessions()
			if err != nil {
				return err
			}
			if len(sessions) == 0 {
				fmt.Println("No active sessions.")
				return nil
			}

			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(tw, "TOKEN (prefix)\tEXPIRES")
			fmt.Fprintln(tw, "-------------\t-------")
			for _, s := range sessions {
				tok := s.Token
				if len(tok) > 16 {
					tok = tok[:16] + "…"
				}
				fmt.Fprintf(tw, "%s\t%s\n", tok, s.Expiry.Format("2006-01-02 15:04:05"))
			}
			tw.Flush()
			return nil
		},
	}
}

// ── session purge ─────────────────────────────────────────────────────────────

func authCmdSessionPurge(dbPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "purge",
		Short: "Delete all expired sessions from the database",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := authOpen(dbPath)
			if err != nil {
				return err
			}
			defer m.Close()

			n, err := m.PurgeSessions()
			if err != nil {
				return err
			}
			fmt.Printf("✓ Purged %d expired session(s)\n", n)
			return nil
		},
	}
}
