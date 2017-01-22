package handler

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"../session"
	"../static"

	"github.com/tstranex/u2f"
)

// registerHandler handles registering a new U2F token.
type registerHandler struct {
	sp *sessionProvider

	tmpl *template.Template
}

func newRegister(sp *sessionProvider) (http.Handler, error) {
	urt, err := static.Asset("templates/u2f-register.html")
	if err != nil {
		return nil, fmt.Errorf("could not get U2F registration template: %v", err)
	}
	tmpl, err := template.New("u2f-register").Parse(string(urt))
	if err != nil {
		return nil, fmt.Errorf("could not parse U2F registration template: %v", err)
	}

	return &registerHandler{
		sp:   sp,
		tmpl: tmpl,
	}, nil
}

func (rh registerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := rh.sp.GetSession(w, r)
	if sess == nil {
		return
	}

	switch r.Method {
	case http.MethodGet:
		c, err := sess.GenerateRegisterChallenge()
		if err != nil {
			log.Printf("Could not create U2F registration challenge: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		req := u2f.NewWebRegisterRequest(c, sess.GetRegistrations())

		var buf bytes.Buffer
		if err := rh.tmpl.Execute(&buf, req); err != nil {
			log.Printf("Could not execute U2F registration template: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		newStatic(buf.String(), "text/html; charset=utf-8").ServeHTTP(w, r)

	case http.MethodPost:
		c, err := sess.GetRegisterChallenge()
		if err == session.ErrNoChallenge {
			log.Printf("Got POST to /register without a challenge")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		} else if err != nil {
			log.Printf("Could not retrieve U2F registration challenge: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		var resp u2f.RegisterResponse
		if err := json.NewDecoder(r.Body).Decode(&resp); err != nil {
			log.Printf("Could not parse U2F registration response: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		reg, err := u2f.Register(resp, *c, nil)
		if err != nil {
			log.Printf("Could not complete U2F registration: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		regBytes, err := reg.MarshalBinary()
		if err != nil {
			log.Printf("Could not marshal U2F registration: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		newStatic(base64.RawStdEncoding.EncodeToString(regBytes), "text/plain; charset=utf-8").ServeHTTP(w, r)

	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}
