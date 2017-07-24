package main

import (
	"flag"
	"log"
	"time"

	"github.com/BranLwyd/harpocrates/alert"
	"github.com/BranLwyd/harpocrates/handler/handler"
	"github.com/BranLwyd/harpocrates/session"
)

// config stores a harpd server configuration.
type config struct {
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

func main() {
	flag.Parse()

	// Parse config & prepare session handler.
	cfg, se, cs := parseConfig()
	sessionDuration := time.Duration(cfg.SessionDurationSecs * float64(time.Second))
	var alerter alert.Alerter
	if cfg.AlertCmd != "" {
		alerter = alert.NewCommand(cfg.AlertCmd)
	} else {
		alerter = alert.NewLog()
	}
	sh, err := session.NewHandler(se, cfg.PassDir, cfg.HostName, cfg.U2FRegistrations, sessionDuration, cs, cfg.NewSessionRate, alerter)
	if err != nil {
		log.Fatalf("Could not create session handler: %v", err)
	}

	// Start serving.
	serve(cfg, handler.NewContent(sh))
}
