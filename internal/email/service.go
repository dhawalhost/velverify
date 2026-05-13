package email

import (
	"context"
	"fmt"
	"net/smtp"
	"os"
	"strings"

	"go.uber.org/zap"
)

// Service defines the interface for sending emails.
type Service interface {
	SendEmail(ctx context.Context, to []string, subject, body string) error
	SendPasswordSetupLink(ctx context.Context, email, name, link, mode string) error
}

type smtpService struct {
	host     string
	port     string
	username string
	password string
	from     string
	logger   *zap.Logger
}

// NewService creates a new email service based on environment variables.
func NewService(logger *zap.Logger) Service {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	username := os.Getenv("SMTP_USERNAME")
	password := os.Getenv("SMTP_PASSWORD")
	from := os.Getenv("SMTP_FROM")

	if from == "" {
		from = "no-reply@wardseal.io"
	}

	if host == "" {
		logger.Warn("SMTP_HOST not set, using mock email service")
		return &mockService{logger: logger, from: from}
	}

	return &smtpService{
		host:     host,
		port:     port,
		username: username,
		password: password,
		from:     from,
		logger:   logger,
	}
}

func (s *smtpService) SendEmail(ctx context.Context, to []string, subject, body string) error {
	msg := []byte(fmt.Sprintf("To: %s\r\n"+
		"From: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-version: 1.0;\r\n"+
		"Content-Type: text/html; charset=\"UTF-8\";\r\n"+
		"\r\n"+
		"%s\r\n", strings.Join(to, ","), s.from, subject, body))

	auth := smtp.PlainAuth("", s.username, s.password, s.host)
	addr := fmt.Sprintf("%s:%s", s.host, s.port)

	s.logger.Info("Sending email", zap.Strings("to", to), zap.String("subject", subject))
	return smtp.SendMail(addr, auth, s.from, to, msg)
}

func (s *smtpService) SendPasswordSetupLink(ctx context.Context, email, name, link, mode string) error {
	subject := "Set up your WardSeal password"
	action := "set up your account"
	if mode == "reset" {
		subject = "Reset your WardSeal password"
		action = "reset your password"
	}

	body := fmt.Sprintf(`
		<html>
		<body>
			<p>Hello %s,</p>
			<p>Please click the link below to %s:</p>
			<p><a href="%s">%s</a></p>
			<p>This link will expire in 72 hours.</p>
			<p>If you did not request this, please ignore this email.</p>
			<br/>
			<p>Best regards,<br/>WardSeal Team</p>
		</body>
		</html>
	`, name, action, link, subject)

	return s.SendEmail(ctx, []string{email}, subject, body)
}

type mockService struct {
	logger *zap.Logger
	from   string
}

func (s *mockService) SendEmail(ctx context.Context, to []string, subject, body string) error {
	s.logger.Info("MOCK EMAIL SENT",
		zap.String("from", s.from),
		zap.Strings("to", to),
		zap.String("subject", subject),
		zap.String("body_preview", body[:min(100, len(body))]))
	return nil
}

func (s *mockService) SendPasswordSetupLink(ctx context.Context, email, name, link, mode string) error {
	s.logger.Info("MOCK PASSWORD SETUP LINK SENT",
		zap.String("email", email),
		zap.String("link", link),
		zap.String("mode", mode))
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
