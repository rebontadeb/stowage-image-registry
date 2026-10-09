// Package regclient is a minimal client for the Distribution HTTP API v2.
package regclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	ErrNotFound = errors.New("not found in registry")
	ErrInvalid  = errors.New("invalid repository or tag")

	repoRe = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
	tagRe  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
)

const manifestAccept = "application/vnd.oci.image.manifest.v1+json," +
	"application/vnd.oci.image.index.v1+json," +
	"application/vnd.docker.distribution.manifest.v2+json," +
	"application/vnd.docker.distribution.manifest.list.v2+json"

// ValidRepo reports whether name is a well-formed repository name (OCI distribution grammar).
func ValidRepo(name string) bool { return len(name) <= 255 && repoRe.MatchString(name) }

type Client struct {
	BaseURL  string // e.g. http://127.0.0.1:5100
	Username string // optional basic auth
	Password string
	HTTP     *http.Client
}

func New(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// NewManaged returns a client for a registry this service itself provisioned: basic auth with the
// internal admin credential, and (for https) no certificate verification, since the hop is to our
// own instance on a local/cluster address that user-supplied certs rarely name.
func NewManaged(baseURL, user, pass string) *Client {
	c := New(baseURL)
	c.Username, c.Password = user, pass
	if strings.HasPrefix(baseURL, "https://") {
		c.HTTP.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	return c
}

func (c *Client) do(ctx context.Context, method, path string, hdr map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return c.HTTP.Do(req)
}

// getJSON GETs path, decodes into v and returns the Link header's next path ("" if none).
func (c *Client) getJSON(ctx context.Context, path string, v any) (string, error) {
	resp, err := c.do(ctx, "GET", path, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return "", ErrNotFound
	case resp.StatusCode != http.StatusOK:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("registry GET %s: %d: %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return "", err
	}
	return nextLink(resp.Header.Get("Link")), nil
}

// nextLink extracts the target of `<...>; rel="next"`.
func nextLink(h string) string {
	if h == "" {
		return ""
	}
	start, end := strings.Index(h, "<"), strings.Index(h, ">")
	if start < 0 || end < start {
		return ""
	}
	return h[start+1 : end]
}

func (c *Client) Catalog(ctx context.Context) ([]string, error) {
	var all []string
	path := "/v2/_catalog?n=100"
	for path != "" {
		var page struct {
			Repositories []string `json:"repositories"`
		}
		next, err := c.getJSON(ctx, path, &page)
		if err != nil {
			return nil, err
		}
		all = append(all, page.Repositories...)
		path = next
	}
	if all == nil {
		all = []string{}
	}
	return all, nil
}

func (c *Client) Tags(ctx context.Context, repo string) ([]string, error) {
	if !repoRe.MatchString(repo) {
		return nil, ErrInvalid
	}
	var all []string
	path := "/v2/" + repo + "/tags/list?n=100"
	for path != "" {
		var page struct {
			Tags []string `json:"tags"`
		}
		next, err := c.getJSON(ctx, path, &page)
		if err != nil {
			return nil, err
		}
		all = append(all, page.Tags...)
		path = next
	}
	if all == nil {
		all = []string{}
	}
	return all, nil
}

// Digest resolves a tag (or digest) to its manifest digest.
func (c *Client) Digest(ctx context.Context, repo, ref string) (string, error) {
	if !repoRe.MatchString(repo) || (!tagRe.MatchString(ref) && !strings.HasPrefix(ref, "sha256:")) {
		return "", ErrInvalid
	}
	resp, err := c.do(ctx, "HEAD", "/v2/"+repo+"/manifests/"+url.PathEscape(ref), map[string]string{"Accept": manifestAccept})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return "", ErrNotFound
	case resp.StatusCode != http.StatusOK:
		return "", fmt.Errorf("registry HEAD manifest: %d", resp.StatusCode)
	}
	d := resp.Header.Get("Docker-Content-Digest")
	if d == "" {
		return "", errors.New("registry returned no Docker-Content-Digest")
	}
	return d, nil
}

// DeleteManifest removes the manifest by digest (all tags pointing at it go away).
func (c *Client) DeleteManifest(ctx context.Context, repo, digest string) error {
	if !repoRe.MatchString(repo) || !strings.HasPrefix(digest, "sha256:") {
		return ErrInvalid
	}
	resp, err := c.do(ctx, "DELETE", "/v2/"+repo+"/manifests/"+digest, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusAccepted, http.StatusOK:
		return nil
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusMethodNotAllowed:
		return errors.New("manifest deletion is disabled (storage.delete.enabled)")
	}
	return fmt.Errorf("registry DELETE manifest: %d", resp.StatusCode)
}

// Ping reports whether the registry process answers. 200 and 401 both mean it is up.
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.do(ctx, "GET", "/v2/", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
		return nil
	}
	return fmt.Errorf("registry /v2/: %d", resp.StatusCode)
}
