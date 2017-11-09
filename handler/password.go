package handler

import (
	"bytes"
	"html/template"
	"log"
	"net/http"
	"path"
	"strings"

	"github.com/BranLwyd/harpocrates/assets"
	"github.com/BranLwyd/harpocrates/password"
	"github.com/BranLwyd/harpocrates/session"
)

var (
	entryViewTmpl = template.Must(template.New("entry-view").Funcs(map[string]interface{}{
		"name": path.Base,
		"dir": func(entryPath string) string {
			d := path.Dir(entryPath)
			if d == "/" {
				return d
			}
			return d + "/"
		},
	}).Parse(string(assets.MustAsset("templates/entry-view.html"))))

	dirViewTmpl = template.Must(template.New("directory-view").Funcs(map[string]interface{}{
		"name": path.Base,
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
	}).Parse(string(assets.MustAsset("templates/directory-view.html"))))
)

// passwordHandler handles all password content (i.e. the main UI).
// It assumes it can get an authenticated session from the request.
type passwordHandler struct{}

func newPassword() *passwordHandler {
	return &passwordHandler{}
}

func (ph passwordHandler) authPath(r *http.Request) (string, error) {
	// If this is requesting an entry, require U2F authentication per page.
	// If this is requesting a directory, only require that some U2F authentication has been done.
	path, isDir := parsePath(r.URL.Path)
	if isDir {
		return authAny, nil
	}
	return path, nil
}

func (ph passwordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess == nil {
		log.Printf("Could not get authenticated session in password handler")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	path, isDir := parsePath(r.URL.Path)
	if isDir {
		ph.serveDirectoryHTTP(w, r, sess, path)
	} else {
		ph.serveEntryHTTP(w, r, sess, path)
	}
}

func (ph passwordHandler) serveEntryHTTP(w http.ResponseWriter, r *http.Request, sess *session.Session, entryPath string) {
	// Get entry content.
	content, err := sess.GetStore().Get(entryPath)
	if err != nil {
		if err == password.ErrNoEntry {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
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
		// Ignore if not in the current directory.
		if !strings.HasPrefix(pe, dirPath) {
			continue
		}

		// Ignore if a hidden file or directory.
		if pe[len(dirPath)] == '.' {
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

func parsePath(p string) (cleanedPath string, isDir bool) {
	isDir = strings.HasSuffix(p, "/")
	cleanedPath = path.Clean(p)

	// path.Clean() removes any trailing slashes, unless the path is just a slash.
	// Put the trailing slash back if the request was for a directory.
	if isDir && !strings.HasSuffix(cleanedPath, "/") {
		cleanedPath = cleanedPath + "/"
	}

	return cleanedPath, isDir
}
