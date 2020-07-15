package handler

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"

	"github.com/e3b0c442/warp"

	"github.com/BranLwyd/harpocrates/harpd/assets"
	"github.com/BranLwyd/harpocrates/harpd/session"
)

var mfaRegisterTmpl = template.Must(template.New("mfa-register").Parse(string(assets.MustAsset("harpd/assets/templates/mfa-register.html"))))

// registerHandler handles registering a new MFA token.
// It assumes it can get an authenticated session from the request.
type registerHandler struct{}

func newRegister() *registerHandler {
	return &registerHandler{}
}

func (rh registerHandler) authPath(r *http.Request) (string, error) {
	// The registration page is available without MFA if there are no MFA registrations.
	if !sessionFrom(r).HasRegisteredMFADevice() {
		return "", nil
	}
	return authAny, nil
}

func (rh registerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess == nil {
		log.Printf("Could not get authenticated session in MFA registration handler")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodGet:
		c, err := sess.GenerateMFARegistrationChallenge()
		if err != nil {
			log.Printf("Could not create MFA registration challenge: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		cBytes, err := json.Marshal(c)
		if err != nil {
			log.Printf("Could not marshal MFA registration challenge: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		serveTemplate(w, r, mfaRegisterTmpl, string(cBytes))

	case http.MethodPost:
		cred := &warp.AttestationPublicKeyCredential{}
		if err := json.NewDecoder(r.Body).Decode(cred); err != nil {
			log.Printf("Could not parse MFA registration response: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		encodedCred, err := sess.CompleteMFARegistration(cred)
		if err == session.ErrNoChallenge {
			log.Printf("Got POST to /register without a challenge")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		} else if err != nil {
			log.Printf("Could not complete MFA registration: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		newStatic([]byte(encodedCred), "text/plain; charset=utf-8").ServeHTTP(w, r)

	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}
