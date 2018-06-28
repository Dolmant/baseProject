package main

import (
	"context"
	"log"

	"bitbucket.org/dolmant/gold/auth-service/pb"
	"bitbucket.org/dolmant/gold/auth-service/pkg/authclient"
	"bitbucket.org/dolmant/gold/auth-service/pkg/authclient/decrypt"
)

func main() {
	file := ""
	conn, AuthService := client.NewAuthServiceClient(false, &file, "localhost:8097", "")
	defer conn.Close()

	result, err := AuthService.Encrypt(context.Background(), &pb.EncryptRequest{Secret: "test"})
	if err != nil {
		log.Printf("error: %s", err.Error())
	}

	Decrypter, err := decrypt.New("")

	if err != nil {
		log.Printf("error: %s", err.Error())
	} else {
		retry, err := Decrypter.Decrypt(result.Crypto)
		log.Println(retry)
		if err != nil {
			log.Printf("error: %s", err.Error())
		}
	}
}
