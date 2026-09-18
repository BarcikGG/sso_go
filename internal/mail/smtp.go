package mail

import (
	"errors"
	"strings"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

type SMTP struct{ Addr, From, Mode, User, Password string }

func (m SMTP) Send(to, subject, link string) error {
	if m.Addr == "" {
		return errors.New("SSO_SMTP_ADDR is required")
	}
	from := m.From
	if from == "" {
		from = "sso@localhost"
	}
	var c *smtp.Client
	var err error
	switch m.Mode {
	case "plain":
		c, err = smtp.Dial(m.Addr)
	case "tls":
		c, err = smtp.DialTLS(m.Addr, nil)
	case "", "starttls":
		c, err = smtp.DialStartTLS(m.Addr, nil)
	default:
		return errors.New("invalid SSO_SMTP_MODE")
	}
	if err != nil {
		return err
	}
	defer c.Close()
	if m.User != "" {
		if err = c.Auth(sasl.NewPlainClient("", m.User, m.Password)); err != nil {
			return err
		}
	}
	body := "From: " + from + "\r\nTo: " + to + "\r\nSubject: " + subject + "\r\n\r\n" + link + "\r\n"
	if err = c.SendMail(from, []string{to}, strings.NewReader(body)); err != nil {
		return err
	}
	return c.Quit()
}
