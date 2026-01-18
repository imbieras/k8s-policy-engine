package models

import "time"

type Token struct {
	Value     string    `json:"token" gorm:"primaryKey"`
	CreatedAt time.Time `json:"created_at"`
}
