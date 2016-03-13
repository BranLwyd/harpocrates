package main

import (
	"encoding/base64"
	"flag"
	"io/ioutil"
	"log"
	"time"

	"./session"
)

var (
	entityFile      = flag.String("entity_file", "", "File containing PGP entity used to encrypt/decrypt password entries.")
	baseDir         = flag.String("base_dir", "", "Base directory of password store.")
	sessionDuration = flag.Duration("session_duration", time.Minute, "Length of sessions (without interaction).")
)

func main() {
	// Check flags.
	flag.Parse()
	if *entityFile == "" {
		log.Fatalf("--entity_file is required")
	}
	if *baseDir == "" {
		log.Fatalf("--base_dir is required")
	}
	if *sessionDuration <= 0 {
		log.Fatalf("--session_duration must be positive")
	}

	// Create session handler.
	sEntity, err := ioutil.ReadFile(*entityFile)
	if err != nil {
		log.Fatalf("Could not read entity: %v", err)
	}
	sessHandler, err := session.NewHandler(sEntity, *baseDir, *sessionDuration)
	if err != nil {
		log.Fatalf("Could not create session handler: %v", err)
	}

	// XXX test code
	sessID, err := sessHandler.CreateSession([]byte("password"))
	if err != nil {
		log.Fatalf("Could not create session: %v", err)
	}
	log.Printf("Session ID: %v", base64.StdEncoding.EncodeToString([]byte(sessID)))

	log.Printf("before: %v", sessHandler.GetPasswordStore(sessID))
	time.Sleep(*sessionDuration + 1*time.Second)
	log.Printf("after: %v", sessHandler.GetPasswordStore(sessID))
}
