package subscription

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ory/x/sqlxx"
	"time"
)

type SubscriptionType string

const (
	Free    SubscriptionType = "Free"
	Charged                  = "Charged"
)

type SubscriptionStatus string

const (
	Applied SubscriptionStatus = "Applied"
	Granted                    = "Granted"
	Refused                    = "Refused"
)

type Subscription struct {
	// Hash(Requestor+Target+Owner).Target
	ID         string               `json:"id" db:"id"`
	Name       string               `json:"name" db:"name"`
	Content    string               `json:"content" db:"content"`
	Requestor  string               `json:"requestor" db:"requestor"`
	Recipient  string               `json:"recipient" db:"recipient"`
	Owner      string               `json:"owner" db:"owner"`
	Identifier string               `json:"identifier" db:"identifier"`
	Type       SubscriptionType     `json:"type" db:"type"`
	Status     SubscriptionStatus   `json:"status" db:"status"`
	CreatedAt  time.Time            `json:"created_at" db:"created_at"`
	ModifiedAt time.Time            `json:"modified_at" db:"modified_at"`
	ExpiredAt  time.Time            `json:"expired_at" db:"expired_at"`
	Metadata   sqlxx.JSONRawMessage `json:"metadata,omitempty" db:"metadata"`
}

func (entity *Subscription) init() {
	if entity.Name == "" {
		if entity.Requestor != entity.Owner {
			entity.Name = fmt.Sprintf("%s wants to access your data identifier: %s", entity.Requestor, entity.Identifier)
		} else {
			entity.Name = fmt.Sprintf("%s will share your data identifier: %s", entity.Requestor, entity.Identifier)
		}
	}
	if entity.Content == "" {
		entity.Content = fmt.Sprintf("#{entity.Requestor}")
	}
	if entity.Type == "" {
		entity.Type = Free
	}
	if entity.Status == "" {
		entity.Status = Applied
	}
	entity.CreatedAt = time.Now()
	entity.ModifiedAt = time.Now()
	entity.ExpiredAt = entity.CreatedAt.Add(time.Duration(120) * time.Hour)
	h := md5.New()
	h.Write([]byte(entity.Requestor + entity.Identifier + entity.Recipient + entity.Owner))
	hash := hex.EncodeToString(h.Sum([]byte{}))
	entity.ID = string(hash) + "." + entity.Identifier
}

type ApproveResult struct {
	ID     string             `json:"id" db:"id"`
	Owner  string             `json:"owner" db:"owner"`
	Status SubscriptionStatus `json:"status" db:"status"`
}

func (status SubscriptionStatus) IsValid() error {
	switch status {
	case Applied, Granted, Refused:
		return nil
	}
	return errors.New("invalid SubscriptionStatus type")
}

func (st SubscriptionType) IsValid() error {
	switch st {
	case Free, Charged:
		return nil
	}
	return errors.New("invalid SubscriptionType type")
}
