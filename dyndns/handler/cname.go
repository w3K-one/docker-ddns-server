package handler

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/w3K-one/docker-ddns-server/dyndns/model"
	"github.com/w3K-one/docker-ddns-server/dyndns/nswrapper"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// ListCNames fetches all cnames from database and lists them on the website.
func (h *Handler) ListCNames(c echo.Context) (err error) {
	// Auth check removed - middleware handles this
	cnames := new([]model.CName)
	if err = h.DB.Preload("Target").Find(cnames).Error; err != nil {
		return c.JSON(http.StatusBadRequest, &Error{err.Error()})
	}

	return c.Render(http.StatusOK, "listcnames", echo.Map{
		"cnames": cnames,
		"title":  h.Title,
		"logoPath": h.LogoPath,
		"poweredBy":    h.PoweredBy,
		"poweredByUrl": h.PoweredByUrl,
	})
}

// AddCName just renders the "add cname" website.
// Therefore all host entries from the database are being fetched.
func (h *Handler) AddCName(c echo.Context) (err error) {
	hosts := new([]model.Host)
	if err = h.DB.Find(hosts).Error; err != nil {
		return c.JSON(http.StatusBadRequest, &Error{err.Error()})
	}

	return c.Render(http.StatusOK, "addcname", echo.Map{
		"config": h.Config,
		"hosts":  hosts,
		"title":  h.Title,
		"logoPath": h.LogoPath,
		"poweredBy":    h.PoweredBy,
		"poweredByUrl": h.PoweredByUrl,
	})
}

// CreateCName validates the cname data from the "add cname" website,
// adds the cname entry to the database,
// and adds the entry to the DNS server.
func (h *Handler) CreateCName(c echo.Context) (err error) {
	cname := &model.CName{}
	if err = c.Bind(cname); err != nil {
		return c.JSON(http.StatusBadRequest, &Error{err.Error()})
	}

	host := &model.Host{}
	if err = h.DB.First(host, c.FormValue("target_id")).Error; err != nil {
		return c.JSON(http.StatusBadRequest, &Error{err.Error()})
	}

	cname.Target = *host

	if err = c.Validate(cname); err != nil {
		return c.JSON(http.StatusBadRequest, &Error{err.Error()})
	}

	if err = h.checkUniqueHostname(cname.Hostname, cname.Target.Domain); err != nil {
		return c.JSON(http.StatusBadRequest, &Error{err.Error()})
	}

	if err = h.DB.Create(cname).Error; err != nil {
		return c.JSON(http.StatusBadRequest, &Error{err.Error()})
	}

	if err = nswrapper.UpdateRecord(cname.Hostname, fmt.Sprintf("%s.%s", cname.Target.Hostname, cname.Target.Domain), "CNAME", cname.Target.Domain, cname.Ttl, h.AllowWildcard); err != nil {
		return c.JSON(http.StatusBadRequest, &Error{err.Error()})
	}

	return c.JSON(http.StatusOK, cname)
}

// DeleteCName fetches a cname entry from the database by "id"
// and deletes the database and DNS server entry to it.
func (h *Handler) DeleteCName(c echo.Context) (err error) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, &Error{err.Error()})
	}

	cname := &model.CName{}
	if err = h.DB.Preload("Target").First(cname, id).Error; err != nil {
		return c.JSON(http.StatusBadRequest, &Error{err.Error()})
	}

	err = h.DB.Transaction(func(tx *gorm.DB) error {
		if err = tx.Unscoped().Delete(cname).Error; err != nil {
			return c.JSON(http.StatusBadRequest, &Error{err.Error()})
		}

		return nil
	})
	if err != nil {
		return c.JSON(http.StatusBadRequest, &Error{err.Error()})
	}

	if err = nswrapper.DeleteRecord(cname.Hostname, cname.Target.Domain, h.AllowWildcard); err != nil {
		return c.JSON(http.StatusBadRequest, &Error{err.Error()})
	}

	return c.JSON(http.StatusOK, id)
}
