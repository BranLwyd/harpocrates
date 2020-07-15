// Package server allows running a harpocrates server.
package server

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/BranLwyd/harpocrates/harpd/alert"
	"github.com/BranLwyd/harpocrates/harpd/handler"
	"github.com/BranLwyd/harpocrates/harpd/session"
	"github.com/BranLwyd/harpocrates/secret/key"

	cpb "github.com/BranLwyd/harpocrates/harpd/proto/config_go_proto"
	kpb "github.com/BranLwyd/harpocrates/secret/proto/key_go_proto"
)

// Server provides an interface to the functionality in a harpocrates server
// that differs between the server types (debug, release).
type Server interface {
	// ParseConfig parses the server configuration, returning a Config struct, the key to use, and an
	// MFA counter store.
	ParseConfig() (_ *cpb.Config, _ *kpb.Key, _ error)

	// Serve serves the given HTTP handler. It should not return.
	Serve(*cpb.Config, http.Handler) error
}

func Run(s Server) {
	// Parse config & prepare session handler.
	cfg, k, err := s.ParseConfig()
	if err != nil {
		log.Fatalf("Could not parse configuration: %v", err)
	}
	sessionDuration := time.Duration(cfg.SessionDurationS * float64(time.Second))
	var alerter alert.Alerter
	if cfg.AlertCmd != "" {
		alerter = alert.NewCommand(cfg.AlertCmd)
	} else {
		alerter = alert.NewLog()
	}
	vault, err := key.NewVault(cfg.PassLoc, k)
	if err != nil {
		log.Fatalf("Could not create secret vault: %v", err)
	}
	sh, err := session.NewHandler(vault, fmt.Sprintf("https://%s", cfg.HostName), cfg.MfaReg, sessionDuration, cfg.NewSessionRate, alerter)
	if err != nil {
		log.Fatalf("Could not create session handler: %v", err)
	}

	// Start serving.
	log.Fatalf("Error while serving: %v", s.Serve(cfg, handler.NewContent(sh)))
}
