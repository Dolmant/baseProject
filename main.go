package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/mux"

	"github.com/rs/cors"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

// Init constructs the server and routes. With a bigger project this might be separated into different files and accept config options
func main() {
	log.Printf("Server logging started at: %s", time.Now())
	ex, err := os.Executable()
	check(err)
	exPath := filepath.Dir(ex)

	mux := mux.NewRouter()

	fs := http.FileServer(http.Dir(exPath + string(os.PathSeparator) + "SPA" + string(os.PathSeparator) + "dist"))

	mux.PathPrefix("/dist/").Handler(http.StripPrefix("/dist/", fs))

	fs = http.FileServer(http.Dir(exPath + string(os.PathSeparator) + "SPA" + string(os.PathSeparator) + "assets"))

	mux.PathPrefix("/assets/").Handler(http.StripPrefix("/assets/", fs))

	genericHandle := func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, exPath+string(os.PathSeparator)+"SPA"+string(os.PathSeparator)+"/index.html")
	}
	mux.PathPrefix("/").HandlerFunc(genericHandle)

	handler := cors.Default().Handler(mux)
	fmt.Println("serving")
	err = http.ListenAndServe(":8079", handler)
	if err != nil {
		log.Fatalf("Failed to serve, %s", err.Error())
	}
}
