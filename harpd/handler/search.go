package handler

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"
	"golang.org/x/text/search"

	"github.com/BranLwyd/harpocrates/harpd/assets"
)

var (
	searchTmpl = template.Must(template.New("search").Funcs(map[string]interface{}{
		"relative": func(entryPath string) string { return strings.TrimPrefix(entryPath, "/") },
	}).Parse(string(assets.MustAsset("harpd/assets/templates/search.html"))))
)

// searchHandler handles searching & the search UI.
type searchHandler struct{}

func newSearch() *searchHandler {
	return &searchHandler{}
}

func (searchHandler) authPath(r *http.Request) (string, error) {
	matches, err := performSearch(r)
	if err != nil {
		return "", fmt.Errorf("couldn't perform search: %w", err)
	}
	if len(matches) == 1 {
		// Authenticate against the page we'll be forwarding to,
		// since we're about to forward to it.
		return matches[0], nil
	}
	return authAny, nil
}

func (searchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	query := r.FormValue("q")
	if query == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
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
		http.Redirect(w, r, matches[0], http.StatusSeeOther)
		return
	}

	// There are zero or multiple results. Show the results to the user.
	serveTemplate(w, r, searchTmpl, struct {
		Query   string
		Matches []string
	}{query, matches})
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
		return nil, fmt.Errorf("couldn't list entries: %w", err)
	}
	var matches []string
	for _, e := range allEntries {
		// Ignore hidden entries.
		if strings.Index(e, "/.") != -1 {
			continue
		}

		if i, _ := pat.IndexString(e); i != -1 {
			matches = append(matches, e)
		}
	}
	collate.New(language.English, collate.IgnoreCase).SortStrings(matches)
	return matches, nil
}
