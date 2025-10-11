package main

import (
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/w3K-one/docker-ddns-server/dyndns/handler"
	"github.com/foolin/goview"
	"github.com/foolin/goview/supports/echoview-v4"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

func main() {
	// Set new instance
	e := echo.New()

	e.Logger.SetLevel(log.ERROR)

	e.Use(middleware.Logger())

	// Set Renderer with custom template functions
	e.Renderer = echoview.New(goview.Config{
		Root:      "views",
		Master:    "layouts/master",
		Extension: ".html",
		Funcs: template.FuncMap{
			"year": func() string {
				return time.Now().Format("2006")
			},
			"hasPrefix": func(s, prefix string) bool {
				return strings.HasPrefix(s, prefix)
			},
			"slice": func(s string, start, end int) string {
				if start < 0 {
					start = 0
				}
				if end > len(s) {
					end = len(s)
				}
				if start > end {
					return ""
				}
				return s[start:end]
			},
			"mod": func(i, j int) int {
				return i % j
			},
		},
		DisableCache: true,
	})

	// Set Validator
	e.Validator = &handler.CustomValidator{Validator: validator.New()}

	// Set Statics
	e.Static("/static", "static")

	// Initialize handler
	h := &handler.Handler{}

	// Database connection
	if err := h.InitDB(); err != nil {
		e.Logger.Fatal(err)
	}

	// Parse environment variables and initialize session store
	authAdmin, err := h.ParseEnvs()
	if err != nil {
		e.Logger.Fatal(err)
	}

	// Apply IP blocker middleware globally
	e.Use(h.IPBlockerMiddleware())
	
	// Apply cleanup middleware
	e.Use(h.CleanupMiddleware())

	// Public redirect (root redirects to admin)
	e.GET("/", func(c echo.Context) error {
		return c.Redirect(http.StatusMovedPermanently, "/@/")
	})

	// Admin routes with session-based authentication and HTTPS redirect
	groupAdmin := e.Group("/@")
	
	// Apply HTTPS redirect middleware (only for admin routes)
	groupAdmin.Use(h.HTTPSRedirectMiddleware())
	
	// Login routes (no auth required)
	groupAdmin.GET("/login", h.ShowLoginPage)
	groupAdmin.POST("/login", h.HandleLogin)
	
	// Logout route (no auth required - handles its own session check)
	groupAdmin.GET("/logout", h.HandleLogout)

	// Protected admin routes (require authentication)
	if authAdmin {
		groupAdmin.Use(h.SessionAuthMiddleware())
	}

	// Main admin pages
	groupAdmin.GET("/", h.ListHosts)
	groupAdmin.GET("/hosts", h.ListHosts)
	groupAdmin.GET("/hosts/add", h.AddHost)
	groupAdmin.GET("/hosts/edit/:id", h.EditHost)
	groupAdmin.POST("/hosts/add", h.CreateHost)
	groupAdmin.POST("/hosts/edit/:id", h.UpdateHost)
	groupAdmin.GET("/hosts/delete/:id", h.DeleteHost)

	// CName routes
	groupAdmin.GET("/cnames", h.ListCNames)
	groupAdmin.GET("/cnames/add", h.AddCName)
	groupAdmin.POST("/cnames/add", h.CreateCName)
	groupAdmin.GET("/cnames/delete/:id", h.DeleteCName)

	// Log routes
	groupAdmin.GET("/logs", h.ShowLogs)
	groupAdmin.GET("/logs/host/:id", h.ShowHostLogs)

	// Security management routes
	if authAdmin {
		groupAdmin.GET("/security", h.ShowSecurityDashboard)
		groupAdmin.GET("/security/blocked-ips", h.ShowBlockedIPs)
		groupAdmin.GET("/security/failed-auths", h.ShowFailedAuths)
		groupAdmin.POST("/security/unblock/:ip", h.UnblockIPHandler)
	}

	// DynDNS API endpoints (HTTP allowed, BasicAuth required)
	// These endpoints are used by routers/NVRs and need BasicAuth
	updateRoute := e.Group("/update")
	updateRoute.Use(h.UpdateAuthMiddleware())
	updateRoute.GET("", h.UpdateIP)
	
	nicRoute := e.Group("/nic")
	nicRoute.Use(h.UpdateAuthMiddleware())
	nicRoute.GET("/update", h.UpdateIP)
	
	v2Route := e.Group("/v2")
	v2Route.Use(h.UpdateAuthMiddleware())
	v2Route.GET("/update", h.UpdateIP)
	
	v3Route := e.Group("/v3")
	v3Route.Use(h.UpdateAuthMiddleware())
	v3Route.GET("/update", h.UpdateIP)

	// Health-check endpoint (no auth)
	e.GET("/ping", func(c echo.Context) error {
		u := &handler.Error{
			Message: "OK",
		}
		return c.JSON(http.StatusOK, u)
	})

	// Start server
	e.Logger.Fatal(e.Start(":8080"))
}
