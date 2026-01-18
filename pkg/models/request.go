package models

import "time"

type Request struct {
	ID           string     `json:"id" gorm:"primaryKey"`
	UserIdentity string     `json:"user_identity" gorm:"index"`
	Role         string     `json:"role"`
	Reason       string     `json:"reason"`
	Duration     string     `json:"duration"`
	Status       string     `json:"status" gorm:"index"` // PENDING, APPROVED, REVOKED
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at"`
}

const (
	StatusPending  = "PENDING"
	StatusApproved = "APPROVED"
	StatusRevoked  = "REVOKED"
)
