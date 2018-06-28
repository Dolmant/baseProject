package authservice

import (
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"bitbucket.org/Dolmant/gold/auth-service/pb"
	stripe "github.com/stripe/stripe-go"
	"github.com/stripe/stripe-go/customer"
	"github.com/stripe/stripe-go/sub"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	// How long is the token valid for in minutes
	validTime = time.Minute
)

// NewService returns a naïve, stateless implementation of Service.
func NewService(privateKey *rsa.PrivateKey, db *sql.DB, plans []*stripe.Plan) Service {
	return Service{Key: privateKey, db: db, plans: plans}
}

// Service Type service
type Service struct {
	Key   *rsa.PrivateKey
	db    *sql.DB
	plans []*stripe.Plan
}

type cl struct {
	Secret string
	UserID int64
	jwt.Claims
}

// EncryptWithAuth should
func (s Service) EncryptWithAuth(secret string, public string) (string, error) {
	// Instantiate an encrypter using RSA-OAEP with AES128-GCM. An error would
	// indicate that the selected algorithm(s) are not currently supported.
	publicKey := &s.Key.PublicKey
	encrypter, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{Algorithm: jose.RSA_OAEP, Key: publicKey},
		(&jose.EncrypterOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", err
	}

	customClaims := cl{
		Secret: secret,
		Claims: jwt.Claims{
			Subject:   "auth",
			Issuer:    "stormAnalytics",
			NotBefore: jwt.NewNumericDate(time.Now().UTC()),
			Expiry:    jwt.NewNumericDate(time.Now().Add(validTime).UTC()),
		},
	}

	marshalledClaims, err := json.Marshal(customClaims)
	if err != nil {
		return "", err
	}

	// Encrypt a plaintext in order to get an encrypted JWE object. Also attach
	// some additional authenticated data (AAD) to the object. Note that objects
	// with attached AAD can only be represented using full serialization.
	var aad = []byte(public)
	object, err := encrypter.EncryptWithAuthData(marshalledClaims, aad)
	if err != nil {
		return "", err
	}

	// Serialize the encrypted object using the full serialization format.
	// Alternatively you can also use the compact format here by calling
	// object.CompactSerialize() instead.
	serialized := object.FullSerialize()
	return serialized, nil
}

// Encrypt Thing
func (s Service) Encrypt(secret string) (string, error) {
	// Instantiate an encrypter using RSA-OAEP with AES128-GCM. An error would
	// indicate that the selected algorithm(s) are not currently supported.
	publicKey := &s.Key.PublicKey
	encrypter, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{Algorithm: jose.RSA_OAEP, Key: publicKey},
		(&jose.EncrypterOptions{}).WithType("JWT"),
	)

	if err != nil {
		return "", err
	}

	cl := jwt.Claims{
		Subject:   secret,
		Issuer:    "stormAnalytics",
		NotBefore: jwt.NewNumericDate(time.Now().UTC()),
		Expiry:    jwt.NewNumericDate(time.Now().Add(validTime).UTC()),
	}

	// Encrypt. Calling the encrypter returns an encrypted
	// JWE object, which can then be serialized for output afterwards. An error
	// would indicate a problem in an underlying cryptographic primitive.
	object, err := jwt.Encrypted(encrypter).Claims(cl).CompactSerialize()
	if err != nil {
		return "", err
	}

	return object, nil
}

// Decrypt thing
func (s Service) Decrypt(token string) (string, error) {
	// Parse the serialized, encrypted JWE object. An error would indicate that
	// the given input did not represent a valid message.
	object, err := jose.ParseEncrypted(token)
	if err != nil {
		return "", err
	}

	// Now we can decrypt and get back our original plaintext. An error here
	// would indicate the the message failed to decrypt, e.g. because the auth
	// tag was broken or the message was tampered with.
	decrypted, err := object.Decrypt(s.Key)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

// Validate thing
func (s Service) Validate(token string) bool {
	if token == "" || token == "null" {
		return false
	}
	// Parse the serialized, encrypted JWE object. An error would indicate that
	// the given input did not represent a valid message.
	tok, err := jwt.ParseEncrypted(token)
	if err != nil {
		return false
	}

	out := jwt.Claims{}
	if err = tok.Claims(s.Key, &out); err != nil {
		return false
	}

	err = out.Validate(jwt.Expected{
		Issuer: "stormAnalytics",
		Time:   time.Now().UTC(),
	})

	if err != nil {
		return false
	}

	return true
}

// Subscribe should
func (s Service) Subscribe(request *pb.SubscribeRequest) (*pb.SubscribeReply, error) {
	// todo check for stripe customer id/token (perhaps put it in the auth, update whenever a new customer is created)
	// Create a Customer:

	//todo get these params from the token passed in
	customerParams := &stripe.CustomerParams{
		Email: stripe.String("paying.user@example.com"),
	}
	fmt.Println(request.Token)
	// customerParams.SetSource(request.Token)
	customerParams.SetSource("tok_mastercard")
	cus, err := customer.New(customerParams)
	if err != nil {
		return &pb.SubscribeReply{}, err
	}

	prep, err := s.db.Prepare("UPDATE users SET stripeid = $2 WHERE id = $1")
	if err != nil {
		fmt.Println("ERROR: Wrong query syntax")
		log.Fatal(err)
	}
	defer prep.Close()

	_, err = prep.Query(request.JWTPayload.UserID, cus.ID)

	if err != nil {
		return &pb.SubscribeReply{}, err

	}

	items := []*stripe.SubscriptionItemsParams{
		{
			Plan: stripe.String(s.plans[0].ID),
		},
	}
	params := &stripe.SubscriptionParams{
		Customer: stripe.String(cus.ID),
		Items:    items,
	}
	_, err = sub.New(params)

	if err != nil {
		return &pb.SubscribeReply{}, err
	}

	return &pb.SubscribeReply{}, nil
}

// UnSubscribe Thing
func (s Service) UnSubscribe(request *pb.UnSubscribeRequest) (*pb.UnSubscribeReply, error) {

	prep, err := s.db.Prepare("SELECT stripeid from users WHERE id = $1")
	if err != nil {
		fmt.Println("ERROR: Wrong query syntax")
		log.Fatal(err)
	}
	defer prep.Close()

	result, err := prep.Query(request.JWTPayload.UserID)

	if err != nil {
		return &pb.UnSubscribeReply{}, err
	}
	for result.Next() {
		var stripeid string
		if err := result.Scan(&stripeid); err != nil {
			return &pb.UnSubscribeReply{}, err
		}

		c, err := customer.Get(stripeid, nil)

		if err != nil {
			return &pb.UnSubscribeReply{}, err
		}

		params := &stripe.SubscriptionCancelParams{
			AtPeriodEnd: stripe.Bool(true),
		}
		for _, cSub := range c.Subscriptions.Data {
			_, err := sub.Cancel(cSub.ID, params)
			if err != nil {
				return &pb.UnSubscribeReply{}, err
			}
		}

		return &pb.UnSubscribeReply{}, nil
	}
	return &pb.UnSubscribeReply{}, errors.New("Could not find the users subscription")
}

// Login should
func (s Service) Login(request *pb.LoginRequest) (*pb.LoginReply, error) {
	// Instantiate an encrypter using RSA-OAEP with AES128-GCM. An error would
	// indicate that the selected algorithm(s) are not currently supported.

	publicKey := &s.Key.PublicKey
	encrypter, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{Algorithm: jose.RSA_OAEP, Key: publicKey},
		(&jose.EncrypterOptions{}).WithType("JWT"),
	)
	if err != nil {
		return &pb.LoginReply{}, err
	}

	rows, err := s.db.Query("SELECT id, username, password FROM users")
	if err != nil {
		return &pb.LoginReply{}, err
	}
	defer rows.Close()

	var found bool
	found = false

	var id int64
	for rows.Next() {
		var username, password string
		if err := rows.Scan(&id, &username, &password); err != nil {
			return &pb.LoginReply{}, err
		}
		if username == request.Username {
			pass := bcrypt.CompareHashAndPassword([]byte(password), []byte(request.Password))

			if pass == nil {
				found = true
			}
			break
		}
	}

	if !found {
		return &pb.LoginReply{}, errors.New("Failed, username or password incorrect")
	}

	customClaims := cl{
		UserID: id,
		Claims: jwt.Claims{
			Subject:   "auth",
			Issuer:    "stormAnalytics",
			NotBefore: jwt.NewNumericDate(time.Now().UTC()),
			Expiry:    jwt.NewNumericDate(time.Now().Add(validTime).UTC()),
		},
	}

	serialized, err := jwt.Encrypted(encrypter).Claims(customClaims).CompactSerialize()
	if err != nil {
		return &pb.LoginReply{}, err
	}
	return &pb.LoginReply{Auth: serialized}, nil
}

// NewUser Thing
func (s Service) NewUser(request *pb.NewUserRequest) (*pb.NewUserReply, error) {
	// Instantiate an encrypter using RSA-OAEP with AES128-GCM. An error would
	// indicate that the selected algorithm(s) are not currently supported.

	publicKey := &s.Key.PublicKey
	encrypter, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{Algorithm: jose.RSA_OAEP, Key: publicKey},
		(&jose.EncrypterOptions{}).WithType("JWT"),
	)
	if err != nil {
		return &pb.NewUserReply{}, err
	}

	rows, err := s.db.Query("SELECT username, password FROM users")
	if err != nil {
		return &pb.NewUserReply{}, err
	}
	defer rows.Close()

	var found bool
	found = false
	// Todo just make a better query instead of iterating on all users
	for rows.Next() {
		var username, password string

		if err := rows.Scan(&username, &password); err != nil {
			return &pb.NewUserReply{}, err
		}
		if username == request.Username {
			found = true
			break
		}
	}

	if found {
		return &pb.NewUserReply{}, errors.New("User already exists")
	}

	prep, err := s.db.Prepare("INSERT INTO users (username, password, name) VALUES ($1, $2, $3) RETURNING id")
	if err != nil {
		fmt.Println("ERROR: Wrong query syntax")
		log.Fatal(err)
	}
	defer prep.Close()

	hashed, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)

	if err != nil {
		return &pb.NewUserReply{}, err
	}

	reply, err := prep.Query(
		request.Username,
		hashed,
		request.Name,
	)

	if err != nil {
		return &pb.NewUserReply{}, err
	}
	var id int64

	if reply.Next() {
		err := reply.Scan(&id)
		if err != nil {
			return &pb.NewUserReply{}, err
		}
	} else {
		return &pb.NewUserReply{}, errors.New("No id generated")
	}

	if err != nil {
		return &pb.NewUserReply{}, err
	}

	customClaims := cl{
		UserID: id,
		Claims: jwt.Claims{
			Subject:   "auth",
			Issuer:    "stormAnalytics",
			NotBefore: jwt.NewNumericDate(time.Now().UTC()),
			Expiry:    jwt.NewNumericDate(time.Now().Add(validTime).UTC()),
		},
	}

	serialized, err := jwt.Encrypted(encrypter).Claims(customClaims).CompactSerialize()
	if err != nil {
		return &pb.NewUserReply{}, err
	}
	return &pb.NewUserReply{Auth: serialized}, nil
}
