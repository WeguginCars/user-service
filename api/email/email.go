package email

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/smtp"
	"regexp"
	"strconv"
	"time"
	"wegugin/config"
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
	conf := config.Load()
	// sender data
	from := conf.Email.SENDER_EMAIL
	password := conf.Email.APP_PASSWORD

	// Receiver email address
	to := []string{
		email,
	}

	// smtp server configuration.
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	// Authentication.
	auth := smtp.PlainAuth("", from, password, smtpHost)

	t, err := template.ParseFiles("api/email/template.html")
	if err != nil {
		log.Fatal(err)
	}

	var body bytes.Buffer

	mimeHeaders := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body.Write([]byte(fmt.Sprintf("Subject: Your verification code \n%s\n\n", mimeHeaders)))
	t.Execute(&body, struct {
		Passwd string
	}{

		Passwd: code,
	})

	// Sending email.
	err = smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, body.Bytes())
	if err != nil {
		return err
	}
	fmt.Println("Email sended to:", email)
	return nil
}

func IsValidEmail(email string) bool {
	const emailRegex = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegex)
	return re.MatchString(email)
}
