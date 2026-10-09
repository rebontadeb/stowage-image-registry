// Package web serves the compiled React UI embedded in the binary.
package web

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Minimal container images have no /etc/mime.types, and Go does not know .woff2 on its own.
func init() { _ = mime.AddExtensionType(".woff2", "font/woff2") }

// Handler serves static assets and falls back to index.html so client-side routes survive reloads.
func Handler() http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(sub, p); err != nil {
			if strings.HasPrefix(p, "assets/") || strings.HasPrefix(p, "api/") {
				http.NotFound(w, r)
				return
			}
			r.URL.Path = "/" // unknown path: serve the SPA shell
			p = "index.html"
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}
