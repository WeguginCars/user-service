package email

import (
	"bytes"
	"fmt"
	"html/template"
	"math/rand"
	"net"
	"net/smtp"
	"regexp"
	"strconv"
	"time"
)

func EmailCode(email string) (string, error) {

	// Seed the random number generator with a cryptographically secure value
	source := rand.NewSource(time.Now().UnixNano())
	myRand := rand.New(source)

	// Generate a random 6-digit number (100000 to 999999)
	randomNumber := myRand.Intn(900000) + 100000
	code := strconv.Itoa(randomNumber)

	err := SendEmail(email, code)

	if err != nil {
		return "", err
	}

	return code, nil
}

func SendEmail(email string, code string) error {
	from := "noreply@turbocarsautoexport.com"
	smtpHost := "172.17.0.1"
	smtpPort := "2525"

	to := []string{email}

	t, err := template.ParseFiles("api/email/template.html")
	if err != nil {
		return err
	}

	var body bytes.Buffer
	mimeHeaders := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	headers := fmt.Sprintf("From: TurboCars <%s>\r\n", from)
	headers += fmt.Sprintf("To: %s\r\n", email)
	headers += "Subject: Your verification code\r\n"
	headers += mimeHeaders
	body.Write([]byte(headers))

	t.Execute(&body, struct {
		Passwd string
	}{
		Passwd: code,
	})

	// Manual SMTP connection without TLS
	conn, err := net.Dial("tcp", smtpHost+":"+smtpPort)
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		return err
	}
	defer client.Quit()

	// Set sender
	if err := client.Mail(from); err != nil {
		return err
	}

	// Set recipient
	if err := client.Rcpt(to[0]); err != nil {
		return err
	}

	// Send body
	writer, err := client.Data()
	if err != nil {
		return err
	}

	_, err = writer.Write(body.Bytes())
	if err != nil {
		return err
	}

	err = writer.Close()
	if err != nil {
		return err
	}

	fmt.Println("Email sent to:", email)
	return nil
}

func IsValidEmail(email string) bool {
	const emailRegex = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegex)
	return re.MatchString(email)
}
