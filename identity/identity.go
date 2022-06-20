package identity

import (
	"time"

	"github.com/fuxi-inc/magnolia/pkg/api"
)

type Identity struct {
	ID               string    `json:"userID,omitempty" db:"id"`
	Name             string    `json:"name,omitempty" db:"name"`
	Email            string    `json:"email,omitempty" db:"email"`
	Owner            string    `json:"owner,omitempty" db:"owner"`
	PublicKey        []byte    `json:"publicKey,omitempty" db:"public_key"`
	PrivateKey       []byte    `json:"privateKey,omitempty" db:"private_key"`
	CreationTime     time.Time `json:"creationTime,omitempty" db:"created_at"`
	LastModifiedTime time.Time `json:"lastModifiedTime,omitempty" db:"modified_at"`
}

type responseIdentity struct {
	UserDomainID string `json:"userDomainID"`
	PrivateKey   string `json:"privateKey"`
	Token        string `json:"token"`
}

func (entity *Identity) ToIdentityIdentifier(signature []byte) *api.IdentityIdentifier {
	return &api.IdentityIdentifier{
		Id:               entity.ID,
		Name:             entity.Name,
		ClientID:         "",
		Email:            entity.Email,
		PublicKey:        entity.PublicKey,
		Signature:        signature,
		CreationTime:     0,
		LastModifiedTime: 0,
	}
}

func FromIdentityIdentifier(source *api.IdentityIdentifier) *Identity {
	if source == nil {
		return nil
	}

	entity := &Identity{}
	entity.CreationTime = time.Unix(source.GetCreationTime(), 0)
	entity.LastModifiedTime = time.Unix(source.GetLastModifiedTime(), 0)
	entity.ID = source.GetId()
	entity.Name = source.GetName()
	entity.Email = source.GetEmail()
	entity.PublicKey = source.GetPublicKey()
	return entity

}

func (Identity) TableName() string {
	return "identity_identifier"
}
