package authdecrypt

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"

	"github.com/stripe/stripe-go"

	"bitbucket.org/Dolmant/gold/auth-service/pkg/auth/service"
)

// ServiceInterface is the available methods
type ServiceInterface interface {
	Validate(string) bool
	Decrypt(encrypted string) string
}

// Service is a copy of the main services for wrapping
type Service struct {
	services authservice.Service
}

// Validate is a copy of the main validate
func (s Service) Validate(encrypted string) bool {
	result, _ := s.services.Validate(encrypted)
	return result
}

// Validate is a copy of the main validate
func (s Service) Decrypt(encrypted string) string {
	result, _ := s.services.Decrypt(encrypted)
	return result
}

// New returns a new decrypter using a string key or (if key is blank) your AUTH_PRIVATE_KEY environment variable
func New(key string) (ServiceInterface, error) {
	var finalKey *rsa.PrivateKey
	var err error

	if key != "" {
		block, _ := pem.Decode([]byte(key))

		if block == nil || block.Type != "PRIVATE KEY" {
			err = errors.New("Block not found or not private key")
			return Service{}, err
		}
		finalKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return Service{}, err
		}
	}
	if err != nil || key == "" {
		if err != nil {
		}
		var decodedKey []byte

		envKey := os.Getenv("AUTH_PRIVATE_KEY")

		if envKey == "" {
			decodedKey, err = base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBNnE4QW5adzBURGZDalpucDl5Uk5sbmgzQ3FZb2V5WTNZbUV2NG52MkNydENCRzQ1CkwyaGFjL2ZJYW9DNkgrbDhMNTMyU2x0YUx3MkxHUm5DK0VqUzhjMktrL2pqNHJLZWxVbTQzZmRyNWVsTGpXYXAKYzdLUEErbU5ERGxkTmM3YXc1WGZBdERVWEZMWnJBZFdxK3l3V3dZZ0lCV2xkRDRCbVYxN3N4STYydEN6cUdXMgpvRGo3cXdaYmVLZExKbldEL1VIeUFUcG1RaEZYNWZiVmJMUi9OUW9aNHBxQWdCQUZBUzNoamlRYW9ySjg4OTJyCkRmMVg4Y0ZiT3luZjdWdUJFM3ZjZ0ZRYloyL1NiaER1d1dMMi8rN1VEZTVrUUlmeXJIZkwxUjN3MEw2eDNQYUoKS1RrdmlOeU5PcWRVbVBvQVRiWTJCeDA1VEdmYjdHYXllTWs2blFJREFRQUJBb0lCQUQ0bHA4a1ZFM2hYajhyRgp4b0p1OTZqd0w3My9NRnNrVEtoZHlqdDB6andiU0trNXN5VU53bDVSY0o1YmhtNXErenIwM3NMa0hDYTN0RzBxCk9FcGRwcGJuOGxtcklGWHBMVHVsY1RJK2tqRXBMWnU5WXdSRGRjSDRlQ1NUa0U1dWY5b3Bkd3djMXcrMzFQTE0KWXJSV2tvRVlSeXVYNzkrdmgrYmdMYURISkJUTGk4bTVjbnpRQ1JsUXBSTXZCM2VtZ3NiSFJsNTBseGFQOE5DRwpLaHZuV3dOT2taUWh5eld0SkVNbW5sWXVWQUUzVnAzcHRVS05lNndUNVhTbGVSY0pvZmQraWV6ZVhqLy9TQVpnCnRlQkFWWjBaZXNFN04rSDlsMStjUXN5QlNIY2RmbmNyQ3lBelJlMFlmQTdGeVBlMTJrY3JWWXpBN2FCeDVCOEUKamd6SzAwRUNnWUVBLzRZWTZnbkxpaDBqbWMra3VrVGZNcnA3ODNVWmlLd0g0NW9LZTlYTm9kUE8yc2xwZzFtUAptaTh2dUx5ZHpuaTc1ZWFQWVMwdGx0VDBtdENTQWQrWDlTQUpwT2xPRlhqUmJSaFprMlVOdTdENGo1Ylp2ZHlECjE1ZHJZZ1F2MlFvZVZBRzFFbHVzWHBCUnR6dG51NGVONENONmM3b1hKU0lKeFBWdm9CSEZIdEVDZ1lFQTZ4NzIKZlRsNW5VRnpjUFlOUjdqVXdGQzJUK01oRUdaNjNoamUvYnc2cmhRNVJZVDRTK21tUVFNaEpDRnpCNzNoRG0wcQptcGMxZVBWR0tGUGtqNGNibzJybnhsZVRkMzQ1Z0FZbmhLWVJyTTgwT1JFcTkxck45d3NGK2Rpb2c0b1BibmlKCk1WNEsvaUhoK3pscHdtL004elJJMFUwWEo1SnhCWGk3alNzS2lnMENnWUVBaFZuY1FyZWQ2NVJOY2dYMWQraGQKZTBIclVpRDRsR1VETVByQkllTndqMVhVakVXMHRRSFdlYWJLaHVTWWpwcGZwUmx3Rmt6WGovSFBQY1Evam82Nwo1UWMxUVVVb3BQZ0tnNTdEa0xLYU9pdWZiSUJUWGt4bzJlaUIrQU1yWFY5MGVHN3pxb01CTDlDdGRLeWg5REpJCkRvTTFjcFBaWkYyaEw1TFBFSUIxbVNFQ2dZQW9vaHM3SFBtMWdhQXZ2M1lnRlFNL2tUTlFyeElCd1pRdVdlSC8KdTgzd1U3SnFIMGJCNThsQnB3Yk5OYktwZmRrdEl4U2Z6czRBNzNLR2Vha2dYTnNiN05mTllVa3M5M1Y4ZUpQUAp5dHQzSUFBSWRMMFdMbTAxNm9QSDMvZVBkQWFpc3RZUzRBdktTNVRBVS9YQkVvMDY0cWhLODZXeXd3NGhRZkkzCnZWNSs2UUtCZ0NOemlhZ1ZJaGVWQlBndVJueXp0ZXUzMy9aN1d2UHNnQTlyWFJqNGVTVjJQd05Gc3krYnVzN00KcUlxMmtPa0g5Q1ozMHZJdXQ4MHVPdXhDV0ovT1RHQlJ6R2JzVzRHMDNJaWlJZDlXUVhUUlc4OFk3dnlyU2tVZQpqTVpPdTh2RW1LekVYWVNWeDVoTTM2WlhBRmRHRUtaV09ZVU8yN2JmZEt0eXF5UzRIbmErCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0t")
		} else {
			decodedKey, err = base64.StdEncoding.DecodeString(envKey)
		}

		if err != nil {
			return Service{}, err
		}

		block, _ := pem.Decode(decodedKey)

		if block == nil || block.Type != "RSA PRIVATE KEY" {
			err = errors.New("Block not found or not of type RSA PRIVATE KEY")
			return Service{}, err
		}
		finalKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	var emptyPlans []*stripe.Plan
	newDecrypter := Service{services: authservice.NewService(finalKey, &(sql.DB{}), emptyPlans)}

	return newDecrypter, err
}
