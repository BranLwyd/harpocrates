package handler

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path"
	"regexp"
	"strings"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"
	"mvdan.cc/xurls"

	"github.com/BranLwyd/harpocrates/harpd/assets"
	"github.com/BranLwyd/harpocrates/harpd/session"
	"github.com/BranLwyd/harpocrates/secret"
)

var (
	urlRe  = xurls.Strict()
	lineRe = regexp.MustCompile("^(?s)([^\r\n]*)(?:\r?\n(.*))?$") // two capture groups: first is first line, second is remainder (linebreak between first line & remainder is dropped)

	entryTmplFuncs = map[string]interface{}{
		"name": path.Base,
		"dir": func(entryPath string) string {
			d := path.Dir(entryPath)
			if d == "/" {
				return d
			}
			return d + "/"
		},
		"linkify": func(content string) (template.HTML, error) {
			var buf bytes.Buffer
			idx := 0
			for _, m := range urlRe.FindAllStringIndex(content, -1) {
				lo, hi := m[0], m[1]
				url := content[lo:hi]
				if strings.Contains(url, `"`) {
					// This URL would break out of the href attribute. Don't linkify.
					if _, err := buf.WriteString(template.HTMLEscapeString(content[:hi])); err != nil {
						return "", err
					}
					idx = hi
					continue
				}

				if _, err := fmt.Fprintf(&buf, `%s<a href="%s" target="_blank">%s</a>`, template.HTMLEscapeString(content[idx:lo]), url, template.HTMLEscapeString(url)); err != nil {
					return "", err
				}
				idx = hi
			}
			if _, err := buf.WriteString(template.HTMLEscapeString(content[idx:])); err != nil {
				return "", err
			}
			return template.HTML(buf.String()), nil
		},
		"firstLine": func(x string) string { return lineRe.FindStringSubmatch(x)[1] },
		"restLines": func(x string) string { return lineRe.FindStringSubmatch(x)[2] },
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
	}

	entryViewTmpl = template.Must(template.New("entry-view").Funcs(entryTmplFuncs).Parse(string(assets.MustAsset("harpd/assets/templates/entry-view.html"))))
	dirViewTmpl   = template.Must(template.New("directory-view").Funcs(entryTmplFuncs).Parse(string(assets.MustAsset("harpd/assets/templates/directory-view.html"))))
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
	switch {
	case isDir && r.Method == http.MethodGet:
		ph.serveDirectoryViewHTTP(w, r, sess, path)

	case !isDir && r.Method == http.MethodGet:
		ph.serveEntryViewHTTP(w, r, sess, path)

	case !isDir && r.Method == http.MethodPost:
		ph.serveEntryUpdateHTTP(w, r, sess, path)

	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (ph passwordHandler) serveEntryViewHTTP(w http.ResponseWriter, r *http.Request, sess *session.Session, entryPath string) {
	// Randomly generate a new password.
	var passBytes [16]byte
	if _, err := rand.Read(passBytes[:]); err != nil {
		log.Printf("Could not generate password: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	pass := base64.RawURLEncoding.EncodeToString(passBytes[:])

	// Get entry content & serve based on whether the entry exists or not.
	content, err := sess.GetStore().Get(entryPath)
	if err == secret.ErrNoEntry {
		content = ""
	} else if err != nil {
		log.Printf("Could not get entry %q in password handler: %v", entryPath, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	serveTemplate(w, r, entryViewTmpl, struct {
		Path              string
		Content           string
		GeneratedPassword string
	}{entryPath, content, pass})
}

func (ph passwordHandler) serveEntryUpdateHTTP(w http.ResponseWriter, r *http.Request, sess *session.Session, entryPath string) {
	// Check action type.
	if r.FormValue("action") != "update-entry" {
		http.Redirect(w, r, r.URL.RequestURI(), http.StatusSeeOther)
		return
	}

	// Update entry content.
	if content := r.FormValue("content"); content != "" {
		if err := sess.GetStore().Put(entryPath, content); err != nil {
			log.Printf("Could not update entry content: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	} else {
		if err := sess.GetStore().Delete(entryPath); err != nil && err != secret.ErrNoEntry {
			log.Printf("Could not delete entry content: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	// Display new content to user.
	ph.serveEntryViewHTTP(w, r, sess, entryPath)
}

func (ph passwordHandler) serveDirectoryViewHTTP(w http.ResponseWriter, r *http.Request, sess *session.Session, dirPath string) {
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
	collate.New(language.English, collate.IgnoreCase).SortStrings(entries)
	collate.New(language.English, collate.IgnoreCase).SortStrings(subdirs)

	// If this directory is nonexistent, forward to the parent directory (assuming we aren't already at the root directory).
	if dirPath != "/" && len(subdirs) == 0 && len(entries) == 0 {
		// Call path.Dir twice: the first call just removes the trailing slash.
		parentPath := path.Dir(path.Dir(dirPath))
		if !strings.HasSuffix(parentPath, "/") {
			parentPath = parentPath + "/"
		}
		http.Redirect(w, r, parentPath, http.StatusSeeOther)
		return
	}

	// Render entries/subdirectories.
	serveTemplate(w, r, dirViewTmpl, struct {
		Path           string
		Entries        []string
		Subdirectories []string
	}{dirPath, entries, subdirs})
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
