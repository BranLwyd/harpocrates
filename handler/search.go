package handler

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path"
	"strings"

	"golang.org/x/text/language"
	"golang.org/x/text/search"

	"../static"
)

var (
	searchTmpl = template.Must(template.New("search").Funcs(map[string]interface{}{}).Parse(string(static.MustAsset("templates/search.html"))))
)

// searchHandler handles searching & the search UI.
type searchHandler struct{}

func newSearch() *searchHandler {
	return &searchHandler{}
}

func (searchHandler) authPath(r *http.Request) (string, error) {
	matches, err := performSearch(r)
	if err != nil {
		return "", fmt.Errorf("could not perform search: %v", err)
	}
	if len(matches) == 1 {
		// Authenticate against the page we'll be forwarding to,
		// since we're about to forward to it.
		return path.Join("/p", matches[0]), nil
	}
	return authAny, nil
}

func (searchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("q")
	if query == "" {
		http.Redirect(w, r, "/p/", http.StatusSeeOther)
		return
	}
	matches, err := performSearch(r)
	if err != nil {
		log.Printf("Could not perform search: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// If there's only one result, redirect the user to it.
	if len(matches) == 1 {
		http.Redirect(w, r, path.Join("/p/", matches[0]), http.StatusSeeOther)
		return
	}

	// There are zero or multiple results. Show the results to the user.
	data := struct {
		Query   string
		Matches []string
	}{query, matches}
	var buf bytes.Buffer
	if err := searchTmpl.Execute(&buf, data); err != nil {
		log.Printf("Could not execute search template: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	newStatic(buf.Bytes(), "text/html; charset=utf-8").ServeHTTP(w, r)
}

func performSearch(r *http.Request) ([]string, error) {
	query := r.FormValue("q")
	if query == "" {
		return nil, nil
	}
	pat := search.New(language.English, search.IgnoreCase).Compile([]byte(query))

	sess := sessionFrom(r)
	allEntries, err := sess.GetStore().List()
	if err != nil {
		return nil, fmt.Errorf("could not list entries: %v", err)
	}
	var matches []string
	for _, e := range allEntries {
		// Ignore hidden entries.
		if strings.Index(e, "/.") != -1 {
			continue
		}

		if i, _ := pat.IndexString(e); i != -1 {
			matches = append(matches, strings.TrimPrefix(e, "/"))
		}
	}
	return matches, nil
}
