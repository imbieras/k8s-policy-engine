package db

import (
	"policy-engine/pkg/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func InitDB(dbPath string) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	err = db.AutoMigrate(&models.Request{}, &models.Token{})
	if err != nil {
		return nil, err
	}

	return db, nil
}
