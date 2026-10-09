package regclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCatalogPaginates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("last") == "" {
			w.Header().Set("Link", `</v2/_catalog?n=100&last=b>; rel="next"`)
			w.Write([]byte(`{"repositories":["a","b"]}`))
			return
		}
		w.Write([]byte(`{"repositories":["c"]}`))
	}))
	defer srv.Close()
	got, err := New(srv.URL).Catalog(context.Background())
	if err != nil || len(got) != 3 || got[2] != "c" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestEmptyCatalogIsNotNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"repositories":[]}`))
	}))
	defer srv.Close()
	got, err := New(srv.URL).Catalog(context.Background())
	if err != nil || got == nil {
		t.Fatalf("got %#v, %v", got, err)
	}
}

func TestDigestAndDelete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "HEAD" && r.URL.Path == "/v2/app/manifests/v1":
			w.Header().Set("Docker-Content-Digest", "sha256:abc")
		case r.Method == "DELETE" && r.URL.Path == "/v2/app/manifests/sha256:abc":
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c, ctx := New(srv.URL), context.Background()

	d, err := c.Digest(ctx, "app", "v1")
	if err != nil || d != "sha256:abc" {
		t.Fatalf("digest %q %v", d, err)
	}
	if err := c.DeleteManifest(ctx, "app", d); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Digest(ctx, "app", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestInputValidation(t *testing.T) {
	c, ctx := New("http://unused"), context.Background()
	for _, repo := range []string{"../etc", "UPPER", "a//b", "a/../b", ""} {
		if _, err := c.Tags(ctx, repo); !errors.Is(err, ErrInvalid) {
			t.Errorf("repo %q: want ErrInvalid, got %v", repo, err)
		}
	}
	if _, err := c.Digest(ctx, "app", "bad/tag"); !errors.Is(err, ErrInvalid) {
		t.Errorf("want ErrInvalid, got %v", err)
	}
	if err := c.DeleteManifest(ctx, "app", "notadigest"); !errors.Is(err, ErrInvalid) {
		t.Errorf("want ErrInvalid, got %v", err)
	}
}

func TestPing(t *testing.T) {
	for code, wantErr := range map[int]bool{200: false, 401: false, 500: true, 404: true} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
		err := New(srv.URL).Ping(context.Background())
		srv.Close()
		if (err != nil) != wantErr {
			t.Errorf("status %d: err=%v", code, err)
		}
	}
	if New("http://127.0.0.1:1").Ping(context.Background()) == nil {
		t.Error("closed port should fail")
	}
}
