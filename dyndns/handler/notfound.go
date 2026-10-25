package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// NotFoundErrorHandler decorates browser page misses while preserving API errors.
func (h *Handler) NotFoundErrorHandler(fallback echo.HTTPErrorHandler) echo.HTTPErrorHandler {
	return func(err error, c echo.Context) {
		var he *echo.HTTPError
		r := c.Request()
		path := r.URL.Path
		api := false
		for _, prefix := range []string{"/api", "/update", "/nic", "/v2", "/v3", "/static"} {
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				api = true
			}
		}
		if c.Response().Committed || !errors.As(err, &he) || he.Code != http.StatusNotFound || r.Method != http.MethodGet || !strings.Contains(r.Header.Get("Accept"), "text/html") || api || c.Path() != "" {
			fallback(err, c)
			return
		}
		c.Response().Header().Set("Cache-Control", "no-store")
		c.Response().Header().Set("Referrer-Policy", "no-referrer")
		if renderErr := c.Render(http.StatusNotFound, "notfound", map[string]interface{}{
			"title": h.Title, "logoPath": h.LogoPath, "poweredBy": h.PoweredBy, "poweredByUrl": h.PoweredByUrl,
		}); renderErr != nil {
			fallback(renderErr, c)
		}
	}
}
