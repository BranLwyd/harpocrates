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

var u2fRegisterTmpl = template.Must(template.New("u2f-register").Parse(string(static.MustAsset("templates/u2f-register.html"))))

// registerHandler handles registering a new U2F token.
// It assumes it can get an authenticated session from the request.
type registerHandler struct{}

func newRegister() http.Handler {
	return &registerHandler{}
}

func (rh registerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess == nil {
		log.Printf("Could not get authenticated session in U2F registration handler")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodGet:
		c, err := sess.GenerateU2FChallenge(r.URL.RequestURI())
		if err != nil {
			log.Printf("Could not create U2F registration challenge: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		req := u2f.NewWebRegisterRequest(c, sess.GetRegistrations())

		nonce, err := cspNonce()
		if err != nil {
			log.Printf("Could not create U2F registration nonce: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		var buf bytes.Buffer
		if err := u2fRegisterTmpl.Execute(&buf, struct {
			Req   *u2f.WebRegisterRequest
			Nonce string
		}{req, nonce}); err != nil {
			log.Printf("Could not execute U2F registration template: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'self'; script-src 'self' 'nonce-%s'", nonce))
		newStatic(buf.Bytes(), "text/html; charset=utf-8").ServeHTTP(w, r)

	case http.MethodPost:
		c, err := sess.GetU2FChallenge(r.URL.RequestURI())
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
		regB64 := make([]byte, base64.RawStdEncoding.EncodedLen(len(regBytes)))
		base64.RawStdEncoding.Encode(regB64, regBytes)
		newStatic(regB64, "text/plain; charset=utf-8").ServeHTTP(w, r)

	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}
