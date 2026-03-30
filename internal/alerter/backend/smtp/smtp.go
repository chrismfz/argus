package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"argus/internal/alerter"
)

type Backend struct {
	host     string
	port     int
	username string
	password string
	from     string
	to       []string
	useTLS   bool
}

func New(host string, port int, username, password, from string, to []string, useTLS bool) *Backend {
	return &Backend{
		host:     host,
		port:     port,
		username: username,
		password: password,
		from:     from,
		to:       to,
		useTLS:   useTLS,
	}
}

func (b *Backend) Name() string { return "smtp" }

func (b *Backend) Send(_ context.Context, e alerter.Event) error {
	if len(b.to) == 0 {
		return fmt.Errorf("smtp: no recipients configured")
	}

	subject := fmt.Sprintf("[argus/%s] %s: %s",
		e.Source, strings.ToUpper(string(e.Severity)), e.Title)

	body := buildBody(e)

	msg := buildMessage(b.from, b.to, subject, body)
	addr := fmt.Sprintf("%s:%d", b.host, b.port)

	if b.useTLS {
		return b.sendTLS(addr, msg)
	}
	return b.sendSTARTTLS(addr, msg)
}

func (b *Backend) sendSTARTTLS(addr string, msg []byte) error {
	auth := smtp.PlainAuth("", b.username, b.password, b.host)
	return smtp.SendMail(addr, auth, b.from, b.to, msg)
}

func (b *Backend) sendTLS(addr string, msg []byte) error {
	tlsCfg := &tls.Config{ServerName: b.host}
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("smtp tls dial: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, b.host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Quit()

	if b.username != "" {
		auth := smtp.PlainAuth("", b.username, b.password, b.host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err := client.Mail(b.from); err != nil {
		return err
	}
	for _, to := range b.to {
		if err := client.Rcpt(to); err != nil {
			return err
		}
	}

	w, err := client.Data()
	if err != nil {
		return err
	}
	defer w.Close()
	_, err = w.Write(msg)
	return err
}

func buildMessage(from string, to []string, subject, body string) []byte {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("From: %s\r\n", from))
	sb.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(to, ", ")))
	sb.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	sb.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return []byte(sb.String())
}

func buildBody(e alerter.Event) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Argus Alert\n"))
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")
	sb.WriteString(fmt.Sprintf("Title    : %s\n", e.Title))
	sb.WriteString(fmt.Sprintf("Severity : %s\n", strings.ToUpper(string(e.Severity))))
	sb.WriteString(fmt.Sprintf("Source   : %s\n", e.Source))
	sb.WriteString(fmt.Sprintf("Time     : %s\n", e.Time.UTC().Format("2006-01-02 15:04:05 UTC")))
	if len(e.Tags) > 0 {
		sb.WriteString("\nDetails:\n")
		for k, v := range e.Tags {
			sb.WriteString(fmt.Sprintf("  %-16s %s\n", k+":", v))
		}
	}
	if e.Body != "" {
		sb.WriteString("\n" + strings.Repeat("-", 60) + "\n")
		sb.WriteString(e.Body + "\n")
	}
	sb.WriteString("\n" + strings.Repeat("-", 60) + "\n")
	sb.WriteString("Sent by Argus NOC — argus.myip.gr\n")
	return sb.String()
}
