package main

import (
	"idp-test-go/entra_oauth2"
	"log"
	"net/http"
)

func main() {

	entraService := entra_oauth2.NewEntraService()

	http.HandleFunc("/", entraService.HandleHome)
	http.HandleFunc("/login", entraService.HandleLogin)
	http.HandleFunc("/auth/callback", entraService.HandleCallback)
	http.HandleFunc("/test/token", entraService.GetToken)

	port := "8080"
	log.Printf("Server running on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
