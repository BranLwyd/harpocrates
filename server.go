// Package server allows running a harpocrates server.
package server

import (
	"log"
	"net/http"
	"time"

	"github.com/BranLwyd/harpocrates/alert"
	"github.com/BranLwyd/harpocrates/counter"
	"github.com/BranLwyd/harpocrates/handler"
	"github.com/BranLwyd/harpocrates/secret/key"
	"github.com/BranLwyd/harpocrates/session"

	pb "github.com/BranLwyd/harpocrates/proto/key_proto"
)

// Server provides an interface to the functionality in a harpocrates server
// that differs between the server types (debug, release).
type Server interface {
	// ParseConfig parses the server configuration, returning a Config
	// struct, the key to use, and a U2F counter store.
	ParseConfig() (_ *Config, _ *pb.Key, _ *counter.Store, _ error)

	// Serve serves the given HTTP handler. It should not return.
	Serve(*Config, http.Handler) error
}

// Config stores a harpd server configuration.
type Config struct {
	HostName            string   `json:"host_name"`          // The host name of the server.
	Email               string   `json:"email"`              // The email address of the server.
	CertDir             string   `json:"cert_dir"`           // The directory to use to store HTTPS certificates.
	PassDir             string   `json:"pass_dir"`           // The directory to use to store encrypted password files.
	KeyFile             string   `json:"key_file"`           // The location of the encrypted key file.
	CounterFile         string   `json:"counter_file"`       // The location of the U2F counter file.
	U2FRegistrations    []string `json:"u2f_regs"`           // The U2F registration blobs.
	AlertCmd            string   `json:"alert_cmd"`          // The command to run when an alert is sent.
	SessionDurationSecs float64  `json:"session_duration_s"` // The length of sessions, in seconds.
	NewSessionRate      float64  `json:"new_session_rate"`   // The rate that new sessions can be created, in Hz.
}

func Run(s Server) {
	// Parse config & prepare session handler.
	cfg, k, cs, err := s.ParseConfig()
	if err != nil {
		log.Fatalf("Could not parse configuration: %v", err)
	}
	sessionDuration := time.Duration(cfg.SessionDurationSecs * float64(time.Second))
	var alerter alert.Alerter
	if cfg.AlertCmd != "" {
		alerter = alert.NewCommand(cfg.AlertCmd)
	} else {
		alerter = alert.NewLog()
	}
	vault, err := key.NewVault(cfg.PassDir, k)
	if err != nil {
		log.Fatalf("Could not create secret vault: %v", err)
	}
	sh, err := session.NewHandler(vault, cfg.HostName, cfg.U2FRegistrations, sessionDuration, cs, cfg.NewSessionRate, alerter)
	if err != nil {
		log.Fatalf("Could not create session handler: %v", err)
	}

	// Start serving.
	err = s.Serve(cfg, handler.NewContent(sh))
	log.Fatalf("Error while serving: %v", err)
}
