package authclient

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"log"

	"bitbucket.org/Dolmant/gold/auth-service/pb"
)

// NewAuthServiceClient returns connection and client. Dont forget to close the connection once you are done
func NewAuthServiceClient(tls bool, caFile *string, serverAddr, serverHostOverride string) (*grpc.ClientConn, pb.AuthsvcClient) {
	var opts []grpc.DialOption
	if tls {
		if *caFile == "" {
			log.Fatal("Failed to create TLS credentials")
		}
		creds, err := credentials.NewClientTLSFromFile(*caFile, serverHostOverride)
		if err != nil {
			log.Fatalf("Failed to create TLS credentials %v", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(serverAddr, opts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}

	client := pb.NewAuthsvcClient(conn)

	return conn, client
}
