package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"text/tabwriter"

	"bitbucket.org/Dolmant/gold/auth-service/pb"
	"bitbucket.org/Dolmant/gold/auth-service/pkg/auth/handlers"
	"bitbucket.org/Dolmant/gold/auth-service/pkg/auth/service"
	"bitbucket.org/Dolmant/gold/auth-service/pkg/middleware"
	"github.com/gin-contrib/cors"
	stripe "github.com/stripe/stripe-go"
	"github.com/stripe/stripe-go/plan"
	"github.com/stripe/stripe-go/product"

	"database/sql"

	_ "github.com/lib/pq"

	"github.com/gin-gonic/gin"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

var createTableStatements = []string{
	`CREATE TABLE IF NOT EXISTS users (
		id serial NOT NULL PRIMARY KEY,
		name varchar(255) NULL,
		username varchar(255) NULL,
		password varchar(255) NULL,
		stripeid varchar(255) NULL
	)`,
}

func main() {
	fs := flag.NewFlagSet("authsvc", flag.ExitOnError)
	var (
		// httpAddr         = fs.String("http-addr", ":8099", "HTTP listen address")
		// grpcAddr         = fs.String("grpc-addr", ":8097", "gRPC listen address")
		// dbAddr           = fs.String("db-addr", "localhost:5432", "Password DB address")
		// statsAddr        = fs.String("stats-addr", "statsd/statsd", "Statsd server address")
		AUTH_PRIVATE_KEY = fs.String("AUTH_PRIVATE_KEY", os.Getenv("AUTH_PRIVATE_KEY"), "private key to use")
	)
	fs.Usage = usageFor(fs, os.Args[0]+" [flags]")
	fs.Parse(os.Args[1:])

	connStr := "user=postgres password=example dbname=gold" + " sslmode=disable" //+ " sslmode=verify-full"
	db, err := sql.Open("postgres", connStr)
	check(err)

	// Dummy query to make sure we have the DB as we cannot do create db if not exists
	_, err = db.Query("SELECT 1 FROM information_schema.tables)")
	if err != nil && err.Error() == `pq: database "gold" does not exist` {
		connStr = "user=postgres password=example" + " sslmode=disable" //+ " sslmode=verify-full"
		db, err = sql.Open("postgres", connStr)
		check(err)
		_, err = db.Exec("CREATE DATABASE gold")
		check(err)
		db.Close()
		connStr = "user=postgres password=example dbname=gold" + " sslmode=disable" //+ " sslmode=verify-full"
		db, err = sql.Open("postgres", connStr)
		check(err)
	}

	for _, stmt := range createTableStatements {
		_, err := db.Exec(stmt)
		check(err)
	}

	defer db.Close()

	// todo start up statsd client
	// client, err := statsd.NewClient(*statsAddr, "test-client")
	// check(err)
	// defer client.Close()

	logger := log.New(os.Stderr, "", log.LstdFlags)

	if err != nil {
		logger.Println("Failed to get statsd client")
	}

	// Build the private key if one exists
	var secretKey *rsa.PrivateKey

	if *AUTH_PRIVATE_KEY != "" {
		logger.Println("Parsing key")
		block, _ := pem.Decode([]byte(*AUTH_PRIVATE_KEY))

		if block == nil || block.Type != "RSA PRIVATE KEY" {
			err = errors.New("Block not found or not of type RSA PRIVATE KEY")
		} else {
			secretKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		}

		if err != nil {
			logger.Println("Generating random key, parsed key invalid")
			secretKey, err = rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
		}
	} else {
		logger.Println("Generating random key, no environment key or flag found. Please specify AUTH_PRIVATE_KEY")
		secretKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
	}

	// TODO:
	// get products.

	stripe.Key = "sk_test_I4eI2ZDVFbqnceJLd4rKrrz4"

	params := &stripe.ProductListParams{}
	params.Filters.AddFilter("limit", "", "3")
	i := product.List(params)
	fmt.Println("Found products:")
	var products []*stripe.Product
	for i.Next() {
		products = append(products, i.Product())
	}

	var plans []*stripe.Plan
	planParams := &stripe.PlanListParams{}
	p := plan.List(planParams)
	for p.Next() {
		plans = append(plans, p.Plan())
	}

	if len(plans) == 0 && len(products) == 0 {
		// create product
		params := &stripe.ProductParams{
			Name: stripe.String("My SaaS Platform"),
			Type: stripe.String(string(stripe.ProductTypeService)),
		}
		prod, _ := product.New(params)
		products = append(products, prod)

		// create plan
		paramsPlann := &stripe.PlanParams{
			ProductID: stripe.String(prod.ID),
			Nickname:  stripe.String("Storm Monthly"),
			Interval:  stripe.String(string(stripe.PlanIntervalMonth)),
			Currency:  stripe.String("aud"),
			Amount:    stripe.Int64(499),
		}
		p, err := plan.New(paramsPlann)
		check(err)
		plans = append(plans, p)
	}

	//TODO pass plans only down to service

	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "HEAD"}
	config.AllowHeaders = []string{"Origin", "Authorization", "Content-Length", "Content-Type"}
	router.Use(cors.New(config))

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "success",
		})
	})

	var authenticationService = authservice.NewService(secretKey, db, plans)

	v1 := router.Group("v1")
	{
		userGroup := v1.Group("user")
		{
			userHandler := authhandlers.NewHandlers(authenticationService)
			publicUserGroup := userGroup.Group("public")
			{
				publicUserGroup.GET("/login", userHandler.Login)
				publicUserGroup.GET("/newuser", userHandler.NewUser)
			}
			privateUserGroup := userGroup.Group("private")
			{
				privateUserGroup.Use(middleware.Authenticated(authenticationService))

				privateUserGroup.GET("/subscribe", userHandler.Subscribe)
				privateUserGroup.GET("/unsubscribe", userHandler.UnSubscribe)
			}
		}
	}

	// todo put this in a different service

	router.StaticFS("/bundled", http.Dir("../../SPA/bundled"))
	router.StaticFS("/assets", http.Dir("../../SPA/assets"))
	router.StaticFile("/", "../../SPA/index.html")

	authenticationService.NewUser(&pb.NewUserRequest{Username: "dylan", Password: "dylan", Name: "dylan"})

	router.Run("127.0.0.1:8079")

}

func usageFor(fs *flag.FlagSet, short string) func() {
	return func() {
		fmt.Fprintf(os.Stderr, "USAGE\n")
		fmt.Fprintf(os.Stderr, "  %s\n", short)
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "FLAGS\n")
		w := tabwriter.NewWriter(os.Stderr, 0, 2, 2, ' ', 0)
		fs.VisitAll(func(f *flag.Flag) {
			fmt.Fprintf(w, "\t-%s %s\t%s\n", f.Name, f.DefValue, f.Usage)
		})
		w.Flush()
		fmt.Fprintf(os.Stderr, "\n")
	}
}
