package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/LCGant/role-auth/internal/config"
)

type VerificationSender interface {
	SendVerification(ctx context.Context, to, token string) error
	SendPasswordReset(ctx context.Context, to, token string) error
	Enabled() bool
	SupportsInternalTokenIssue() bool
}

func NewVerificationSender(cfg config.Config) VerificationSender {
	if strings.TrimSpace(cfg.Notification.BaseURL) != "" {
		return &remoteSender{
			baseURL:       strings.TrimRight(cfg.Notification.BaseURL, "/"),
			internalToken: cfg.Notification.InternalToken,
			timeout:       cfg.Notification.Timeout,
		}
	}
	if strings.TrimSpace(cfg.Mail.SMTPHost) != "" {
		return &smtpSender{cfg: cfg.Mail}
	}
	if strings.TrimSpace(cfg.Mail.OutboxDir) != "" {
		return &outboxSender{cfg: cfg.Mail}
	}
	return nil
}

type smtpSender struct {
	cfg config.MailConfig
}

func (s *smtpSender) Enabled() bool                    { return true }
func (s *smtpSender) SupportsInternalTokenIssue() bool { return false }

func (s *smtpSender) SendVerification(ctx context.Context, to, token string) error {
	return s.send(ctx, to, "Verify your email", verificationBody(s.cfg, token))
}

func (s *smtpSender) SendPasswordReset(ctx context.Context, to, token string) error {
	return s.send(ctx, to, "Reset your password", passwordResetBody(s.cfg, token))
}

func (s *smtpSender) send(ctx context.Context, to, subject, body string) error {
	addr := net.JoinHostPort(s.cfg.SMTPHost, strconv.Itoa(s.cfg.SMTPPort))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	client, err := smtp.NewClient(conn, s.cfg.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{
			ServerName: s.cfg.SMTPHost,
			MinVersion: tls.VersionTLS12,
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return err
		}
	} else if s.cfg.SMTPRequireTLS {
		return errors.New("smtp server does not support STARTTLS")
	}

	if s.cfg.SMTPUsername != "" {
		auth := smtp.PlainAuth("", s.cfg.SMTPUsername, s.cfg.SMTPPassword, s.cfg.SMTPHost)
		if err := client.Auth(auth); err != nil {
			return err
		}
	}

	msg := buildMessage(s.cfg.SMTPFrom, to, subject, body)

	if err := client.Mail(s.cfg.SMTPFrom); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	wc, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write([]byte(msg)); err != nil {
		_ = wc.Close()
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return client.Quit()
}

type outboxSender struct {
	cfg config.MailConfig
}

func (o *outboxSender) Enabled() bool                    { return true }
func (o *outboxSender) SupportsInternalTokenIssue() bool { return true }

func (o *outboxSender) SendVerification(ctx context.Context, to, token string) error {
	return o.write(ctx, "verify", to, verificationBody(o.cfg, token))
}

func (o *outboxSender) SendPasswordReset(ctx context.Context, to, token string) error {
	return o.write(ctx, "reset", to, passwordResetBody(o.cfg, token))
}

type remoteSender struct {
	baseURL       string
	internalToken string
	timeout       time.Duration
}

func (r *remoteSender) Enabled() bool                    { return true }
func (r *remoteSender) SupportsInternalTokenIssue() bool { return false }

func (r *remoteSender) SendVerification(ctx context.Context, to, token string) error {
	return r.send(ctx, "/internal/email-verification", to, token)
}

func (r *remoteSender) SendPasswordReset(ctx context.Context, to, token string) error {
	return r.send(ctx, "/internal/password-reset", to, token)
}

func (r *remoteSender) send(ctx context.Context, path, to, token string) error {
	timeout := r.timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	body, err := json.Marshal(map[string]string{
		"to":    strings.TrimSpace(to),
		"token": strings.TrimSpace(token),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", r.internalToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("notification service returned %d", resp.StatusCode)
	}
	return nil
}

func (o *outboxSender) write(ctx context.Context, prefix, to, body string) error {
	_ = ctx
	if err := os.MkdirAll(o.cfg.OutboxDir, 0o700); err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%d-%s.txt", prefix, time.Now().UTC().UnixNano(), sanitizeFilename(to))
	path := filepath.Join(o.cfg.OutboxDir, name)
	return os.WriteFile(path, []byte(body), 0o600)
}

func buildMessage(from, to, subject, body string) string {
	var b strings.Builder
	b.WriteString("From: ")
	b.WriteString(from)
	b.WriteString("\r\n")
	b.WriteString("To: ")
	b.WriteString(to)
	b.WriteString("\r\n")
	b.WriteString("Subject: ")
	b.WriteString(subject)
	b.WriteString("\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

func verificationBody(cfg config.MailConfig, token string) string {
	token = strings.TrimSpace(token)
	if strings.TrimSpace(cfg.EmailVerificationURLTemplate) != "" {
		return strings.ReplaceAll(cfg.EmailVerificationURLTemplate, "{{token}}", token)
	}
	return fmt.Sprintf(
		"Use this verification token to activate your account:\n\n%s\n\nSubmit it to POST /email/verify/confirm or your frontend verification screen.\n",
		token,
	)
}

func passwordResetBody(cfg config.MailConfig, token string) string {
	token = strings.TrimSpace(token)
	if strings.TrimSpace(cfg.PasswordResetURLTemplate) != "" {
		return strings.ReplaceAll(cfg.PasswordResetURLTemplate, "{{token}}", token)
	}
	return fmt.Sprintf(
		"Use this password reset token to change your password:\n\n%s\n\nSubmit it to POST /password/reset or your frontend reset screen.\n",
		token,
	)
}

func sanitizeFilename(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	replacer := strings.NewReplacer(
		"@", "_at_",
		"/", "_",
		"\\", "_",
		":", "_",
		" ", "_",
	)
	value = replacer.Replace(value)
	if value == "" {
		return "recipient"
	}
	return value
}
