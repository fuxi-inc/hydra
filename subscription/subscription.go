package subscription

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/ory/x/sqlxx"
	"time"
)

type SubscriptionType string

const (
	Free    SubscriptionType = "free"
	Charged                  = "charged"
)

type SubscriptionStatus string

const (
	Applied SubscriptionStatus = "applied"
	Granted                    = "granted"
	Refused                    = "refused"
)

type Subscription struct {
	// Hash(Requestor+Target+Owner).Target
	ID         string               `json:"id" db:"id"`
	Name       string               `json:"name" db:"name"`
	Requestor  string               `json:"requestor" db:"requestor"`
	Target     string               `json:"target" db:"target"`
	Owner      string               `json:"owner" db:"owner"`
	Type       SubscriptionType     `json:"type" db:"type"`
	Status     SubscriptionStatus   `json:"status" db:"status"`
	CreatedAt  time.Time            `json:"created_at" db:"created_at"`
	ModifiedAt time.Time            `json:"modified_at" db:"modified_at"`
	ExpiredAt  time.Time            `json:"expired_at" db:"expired_at"`
	Metadata   sqlxx.JSONRawMessage `json:"metadata,omitempty" db:"metadata"`
}

func (sub *Subscription) init() {
	if sub.Name == "" {
		sub.Name = fmt.Sprintf("%s send an apply for your data identifier: %s", sub.Requestor, sub.Target)
	}
	if sub.Type == "" {
		sub.Type = Free
	}
	if sub.Status == "" {
		sub.Status = Applied
	}
	sub.CreatedAt = time.Now()
	sub.ModifiedAt = time.Now()
	sub.ExpiredAt = sub.CreatedAt.Add(time.Duration(120) * time.Hour)
	h := md5.New()
	h.Write([]byte(sub.Requestor + sub.Target + sub.Owner))
	hash := hex.EncodeToString(h.Sum([]byte{}))
	sub.ID = string(hash) + "." + sub.Target
}

type ApproveResult struct {
	ID     string             `json:"id" db:"id"`
	Owner  string             `json:"owner" db:"owner"`
	Status SubscriptionStatus `json:"status" db:"status"`
}
