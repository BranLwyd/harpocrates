package handler

import (
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"net/http"

	"github.com/tstranex/u2f"

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
	if len(sessionFrom(r).MFARegistrations()) == 0 {
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
		c, err := sess.GenerateMFAChallenge(r.URL.RequestURI())
		if err != nil {
			log.Printf("Could not create MFA registration challenge: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		req := u2f.NewWebRegisterRequest(c, sess.MFARegistrations())
		reqBytes, err := json.Marshal(req)
		if err != nil {
			log.Printf("Could not marshal MFA registration challenge: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		serveTemplate(w, r, mfaRegisterTmpl, string(reqBytes))

	case http.MethodPost:
		c, err := sess.GetMFAChallenge(r.URL.RequestURI())
		if err == session.ErrNoChallenge {
			log.Printf("Got POST to /register without a challenge")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		} else if err != nil {
			log.Printf("Could not retrieve MFA registration challenge: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		var resp u2f.RegisterResponse
		if err := json.NewDecoder(r.Body).Decode(&resp); err != nil {
			log.Printf("Could not parse MFA registration response: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		reg, err := u2f.Register(resp, *c, &u2f.Config{SkipAttestationVerify: true})
		if err != nil {
			log.Printf("Could not complete MFA registration: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		regBytes, err := reg.MarshalBinary()
		if err != nil {
			log.Printf("Could not marshal MFA registration: %v", err)
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
