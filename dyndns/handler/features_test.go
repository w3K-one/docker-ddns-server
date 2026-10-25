package handler

import (
	"bytes"
	"github.com/foolin/goview"
	"github.com/labstack/echo/v4"
	"github.com/w3K-one/docker-ddns-server/dyndns/certificates"

	"html/template"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFeatureRoutesRequireAuthentication(t *testing.T) {
	for _, disabled := range []bool{true, false} {
		h := &Handler{DisableAdminAuth: disabled}
		t.Setenv("DDNS_SESSION_SECRET", strings.Repeat("x", 32))
		if e := h.InitSessionStore(); e != nil {
			t.Fatal(e)
		}
		e := echo.New()
		h.FeatureRoutes(e.Group("/@"))
		for _, path := range []string{"/@/records", "/@/certs", "/@/certs/1/download/privkey.pem"} {
			r := httptest.NewRecorder()
			e.ServeHTTP(r, httptest.NewRequest("GET", path, nil))
			if r.Code != 403 && r.Code != 302 && r.Code != 303 {
				t.Fatalf("%s unprotected: %d", path, r.Code)
			}
		}
	}
}
func TestDownloadsRequireHTTPS(t *testing.T) {
	h := &Handler{}
	c := echo.New().NewContext(httptest.NewRequest("GET", "http://example.test/@/certs/1/download/privkey.pem", nil), httptest.NewRecorder())
	err := h.DownloadCertificate(c)
	if he, ok := err.(*echo.HTTPError); !ok || he.Code != 403 {
		t.Fatal(err)
	}
}
func TestFeatureCSRF(t *testing.T) {
	h := &Handler{DB: testDB(t)}
	t.Setenv("DDNS_SESSION_SECRET", strings.Repeat("x", 32))
	h.InitSessionStore()
	e := echo.New()
	h.FeatureRoutes(e.Group("/@"))
	req := httptest.NewRequest("POST", "/@/records", strings.NewReader("zone=example.test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	ctx := e.NewContext(req, recorder)
	session, _ := h.GetSession(ctx)
	session.Values[SessionAuthKey] = true
	session.Values[SessionExpiresAt] = time.Now().Add(time.Hour).Unix()
	session.Save(req, recorder)
	for _, cookie := range recorder.Result().Cookies() {
		req.AddCookie(cookie)
	}
	recorder = httptest.NewRecorder()
	// Authenticated mutations still require a valid CSRF token.
	e.ServeHTTP(recorder, req)
	if recorder.Code != 400 && recorder.Code != 403 {
		t.Fatal(recorder.Code)
	}
}
func TestFeatureTemplates(t *testing.T) {
	view := goview.New(goview.Config{Root: "../views", Master: "layouts/master", Extension: ".html", Funcs: template.FuncMap{"year": func() string { return "2026" }}})
	for _, name := range []string{"records", "certificates"} {
		var out bytes.Buffer
		data := map[string]interface{}{"title": "Test", "csrf": "fixture", "zone": "example.test", "zones": []string{"example.test"}, "types": []string{"TXT", "MX"}, "sets": []rrView{{"@", "TXT", 60, "<script>alert(1)</script>"}}, "enabled": true, "certs": []certificates.Certificate{{ID: 1, Domains: "*.example.test", Status: "valid", CertPEM: []byte("fixture")}}}
		if e := view.RenderWriter(&out, name, data); e != nil {
			t.Fatal(name, e)
		}
		if strings.Contains(out.String(), "<script>alert(1)</script>") {
			t.Fatal("unescaped record")
		}
		if !strings.Contains(out.String(), "aria-label=\"Certificates\"") {
			t.Fatal("missing accessible navigation")
		}
	}
}
