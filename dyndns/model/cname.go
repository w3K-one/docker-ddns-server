package model

import (
	"gorm.io/gorm"
)

// CName is a dns cname entry.
type CName struct {
	gorm.Model
	Hostname string `gorm:"not null" form:"hostname" validate:"required,min=1"` //Alow 1 character cnames
	Target   Host   `validate:"required"`
	TargetID uint
	Ttl      int `form:"ttl" validate:"required,min=20,max=86400"`
}
