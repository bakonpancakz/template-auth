package tools

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type emailProviderSES struct {
	AccessKey        string
	SecretKey        string
	Region           string
	From             string
	ConfigurationSet string
}

func (e *emailProviderSES) Start(stop context.Context, await *sync.WaitGroup) error {
	e.AccessKey = EMAIL_SES_ACCESS_KEY
	e.SecretKey = EMAIL_SES_SECRET_KEY
	e.Region = EMAIL_SES_REGION
	e.From = EMAIL_SENDER_ADDRESS
	e.ConfigurationSet = EMAIL_SES_CONFIGURATION_SET

	// Test Client by Querying Quota
	form := url.Values{}
	form.Set("Action", "GetSendQuota")

	url := fmt.Sprintf("https://email.%s.amazonaws.com/", e.Region)
	req, err := http.NewRequest("POST", url, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	AmazonSignRequestV4(req, []byte(form.Encode()), e.AccessKey, e.SecretKey, fmt.Sprintf("email.%s.amazonaws.com", e.Region), e.Region, "ses")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("server responded with status %d: %s", res.StatusCode, string(body))
	}

	return nil
}

func (e *emailProviderSES) Send(ctx context.Context, toAddress, subject, htmlBody string) error {
	form := url.Values{}
	form.Set("ConfigurationSetName", e.ConfigurationSet)
	form.Set("Action", "SendEmail")
	form.Set("Source", e.From)
	form.Set("Destination.ToAddresses.member.1", toAddress)
	form.Set("Message.Subject.Data", subject)
	form.Set("Message.Body.Html.Data", htmlBody)
	payload := []byte(form.Encode())

	// Generate Request
	url := fmt.Sprintf("https://email.%s.amazonaws.com/", e.Region)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	host := fmt.Sprintf("email.%s.amazonaws.com", e.Region)
	AmazonSignRequestV4(req, payload, e.AccessKey, e.SecretKey, host, e.Region, "ses")

	// Send Request
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode > 299 {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("server responded with status %d: %s", res.StatusCode, string(body))
	}
	return nil
}
