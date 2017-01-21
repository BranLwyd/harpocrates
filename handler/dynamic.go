package handler

import "net/http"

// dynamicHandler handles all dynamic password content.
type dynamicHandler struct {
	sp *sessionProvider
}

func newDynamic(sp *sessionProvider) (http.Handler, error) {
	return &dynamicHandler{
		sp: sp,
	}, nil
}

func (dh dynamicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := dh.sp.GetSession(w, r)
	if sess == nil {
		return
	}

	// TODO: handle logged-in UI
	staticHandler{content: "Logged in.", contentType: "text/plain; charset=utf-8"}.ServeHTTP(w, r)
}
