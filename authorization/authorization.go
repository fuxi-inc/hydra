package authorization

import (
	"crypto/md5"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type AuthorizationType string

const (
	Free    AuthorizationType = "Free"
	Charged                   = "Charged"
)

type AuthorizationStatus string

const (
	Applied AuthorizationStatus = "Applied"
	Granted                     = "Granted"
	Refused                     = "Refused"
)

type Metadata map[string]string

func (metadata Metadata) Value() (driver.Value, error) {
	if len(metadata) == 0 {
		return "{}", nil
	}
	return json.Marshal(metadata)
}

func (metadata *Metadata) Scan(src interface{}) (err error) {
	var result map[string]string
	switch src.(type) {
	case string:
		err = json.Unmarshal([]byte(src.(string)), &result)
	case []byte:
		err = json.Unmarshal(src.([]byte), &result)
	default:
		return errors.New("incompatible type for Metadata")
	}
	if err != nil {
		return
	}
	*metadata = result
	return nil
}

type Authorization struct {
	// Hash(Requestor+Target+Owner).Target
	ID         string              `json:"id" db:"id"`
	Name       string              `json:"name" db:"name"`
	Content    string              `json:"content" db:"content"`
	Requestor  string              `json:"requestor" db:"requestor"`
	Recipient  string              `json:"viewUserDomainID" db:"recipient"`
	Owner      string              `json:"userDomainID" db:"owner"`
	Identifier string              `json:"dataDomainID" db:"identifier"`
	Type       AuthorizationType   `json:"type" db:"type"`
	Status     AuthorizationStatus `json:"status" db:"status"`
	CreatedAt  time.Time           `json:"created_at" db:"created_at"`
	ModifiedAt time.Time           `json:"modified_at" db:"modified_at"`
	ExpiredAt  time.Time           `json:"expired_at" db:"expired_at"`
	Metadata   Metadata            `json:"metadata,omitempty" db:"metadata"`
}

type AuthorizationParams struct {
	Identifier string `json:"dataDomainID"`
	Owner      string `json:"userDomainID"`
	Recipient  string `json:"viewUserDomainID"`
	//Sign       []byte `json:"sign"`
	Sign string `json:"sign"`
}

type AuthenticationParams struct {
	Identifier string `json:"dataDomainID"`
	Recipient  string `json:"viewUserDomainID"`
	//SignRecipient []byte `json:"signAccessAuth"`
	//Sign          []byte `json:"signPod"`
	SignRecipient string `json:"signAccessAuth"`
	Sign          string `json:"signPod"`
}

func (Authorization) TableName() string {
	return "subscriptions"
}

func (entity *Authorization) init() {
	if entity.Name == "" {
		if entity.Requestor != entity.Owner {
			entity.Name = fmt.Sprintf("%s wants to access your data identifier: %s", entity.Requestor, entity.Identifier)
		} else {
			entity.Name = fmt.Sprintf("%s will share your data identifier: %s", entity.Requestor, entity.Identifier)
		}
	}
	if entity.Content == "" {
		entity.Content = fmt.Sprintf("requestor:%s, target:%s, you can choose grant permission or refuse it.", entity.Requestor, entity.Identifier)
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
	entity.Metadata = map[string]string{}
	h := md5.New()
	h.Write([]byte(entity.Requestor + entity.Identifier + entity.Recipient + entity.Owner))
	hash := hex.EncodeToString(h.Sum([]byte{}))
	entity.ID = string(hash) + "." + entity.Identifier
}

type ApproveResult struct {
	Status AuthorizationStatus `json:"status" db:"status"`
}

func (status AuthorizationStatus) IsValid() error {
	switch status {
	case Applied, Granted, Refused:
		return nil
	}
	return errors.New("invalid AuthorizationStatus type")
}

func (st AuthorizationType) IsValid() error {
	switch st {
	case Free, Charged:
		return nil
	}
	return errors.New("invalid AuthorizationType type")
}

func (entity *Authorization) IsActive() bool {
	if entity.Status != Applied {
		return false
	}
	return true
}
