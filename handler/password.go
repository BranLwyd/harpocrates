package handler

import (
	"bytes"
	"html/template"
	"log"
	"net/http"
	"path"
	"strings"

	"../session"
	"../static"
)

var (
	entryViewTmpl = template.Must(template.New("entry-view").Funcs(map[string]interface{}{
		"name": func(entryPath string) string { return path.Base(entryPath) },
		"dir": func(entryPath string) string {
			d := path.Dir(entryPath)
			if d == "/" {
				return d
			}
			return d + "/"
		},
	}).Parse(string(static.MustAsset("templates/entry-view.html"))))

	dirViewTmpl = template.Must(template.New("directory-view").Funcs(map[string]interface{}{
		"name": func(dirPath string) string { return path.Base(dirPath) },
		"parentDir": func(dirPath string) string {
			if dirPath == "/" {
				return ""
			}
			// Call path.Dir twice: the first call just removes the
			// trailing slash.
			pd := path.Dir(path.Dir(dirPath))
			if pd == "/" {
				return pd
			}
			return pd + "/"
		},
	}).Parse(string(static.MustAsset("templates/directory-view.html"))))
)

// passwordHandler handles all password content (i.e. the main UI).
// It assumes it can get an authenticated session from the request.
type passwordHandler struct{}

func newPassword() http.Handler {
	return &passwordHandler{}
}

func (ph passwordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess == nil {
		log.Printf("Could not get authenticated session in password handler")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Check for trailing slash before cleaning, since path.Clean removes
	// any trailing slashes.
	// TODO: unify path handling between this code & login.go's needU2F
	isEntryRequest := !strings.HasSuffix(r.URL.Path, "/")
	entryPath := path.Clean(r.URL.Path)
	if !isEntryRequest {
		entryPath = entryPath + "/"
	}
	if !strings.HasPrefix(entryPath, "/p") {
		log.Printf("Password handler got unexpected path %q", entryPath)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	entryPath = strings.TrimPrefix(entryPath, "/p")

	if isEntryRequest {
		ph.serveEntryHTTP(w, r, sess, entryPath)
	} else {
		ph.serveDirectoryHTTP(w, r, sess, entryPath)
	}
}

func (ph passwordHandler) serveEntryHTTP(w http.ResponseWriter, r *http.Request, sess *session.Session, entryPath string) {
	// Get entry content.
	// TODO: return 404 for file-not-found instead of 500
	content, err := sess.GetStore().Get(entryPath)
	if err != nil {
		log.Printf("Could not get entry %q in password handler: %v", entryPath, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Render page.
	data := struct {
		Path    string
		Content string
	}{entryPath, content}
	var buf bytes.Buffer
	if err := entryViewTmpl.Execute(&buf, data); err != nil {
		log.Printf("Could not execute entry view template: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	newStatic(buf.Bytes(), "text/html; charset=utf-8").ServeHTTP(w, r)
}

func (ph passwordHandler) serveDirectoryHTTP(w http.ResponseWriter, r *http.Request, sess *session.Session, dirPath string) {
	pathEntries, err := sess.GetStore().List()
	if err != nil {
		log.Printf("Could not get entry list in password handler: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Find direct subdirectories and entries.
	var entries []string
	var subdirs []string
	for _, pe := range pathEntries {
		if !strings.HasPrefix(pe, dirPath) {
			continue
		}
		idx := strings.Index(pe[len(dirPath):], "/")
		if idx == -1 {
			entries = append(entries, pe)
		} else {
			// Only include directory entries if they're not already included.
			pe = pe[:len(dirPath)+idx]
			if len(subdirs) == 0 || subdirs[len(subdirs)-1] != pe {
				subdirs = append(subdirs, pe)
			}
		}
	}

	if len(subdirs) == 0 && len(entries) == 0 {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	// Render them.
	data := struct {
		Path           string
		Entries        []string
		Subdirectories []string
	}{dirPath, entries, subdirs}
	var buf bytes.Buffer
	if err := dirViewTmpl.Execute(&buf, data); err != nil {
		log.Printf("Could not execute directory view template: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	newStatic(buf.Bytes(), "text/html; charset=utf-8").ServeHTTP(w, r)
}
