package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

type notFoundRenderer struct{}

func (notFoundRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	_, err := io.WriteString(w, "game404")
	return err
}

func TestBrowserNotFoundPreservesAPIResponses(t *testing.T) {
	for _, tc := range []struct {
		method, path, accept string
		game                 bool
	}{
		{"GET", "/missing", "text/html", true},
		{"HEAD", "/missing", "text/html", false},
		{"POST", "/missing", "text/html", false},
		{"GET", "/missing", "application/json", false},
		{"GET", "/api/missing", "text/html", false},
		{"GET", "/nic/missing", "text/html", false},
		{"GET", "/v2/missing", "text/html", false},
		{"GET", "/static/missing.js", "text/html", false},
		{"GET", "/record-missing", "text/html", false},
	} {
		t.Run(tc.method+tc.path+tc.accept, func(t *testing.T) {
			e := echo.New()
			e.Renderer = notFoundRenderer{}
			h := &Handler{}
			e.HTTPErrorHandler = h.NotFoundErrorHandler(e.DefaultHTTPErrorHandler)
			e.GET("/record-missing", func(c echo.Context) error { return echo.ErrNotFound })
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("Accept", tc.accept)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status %d", rec.Code)
			}
			if strings.Contains(rec.Body.String(), "game404") != tc.game {
				t.Fatalf("unexpected body %s", rec.Body.String())
			}
			if tc.game && rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("404 must not be cached")
			}
		})
	}
}
