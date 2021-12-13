package identity

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	"github.com/fuxi-inc/magnolia/pkg/api"
)

type Identity struct {
	ID               string    `json:"id,omitempty" db:"id"`
	Name             string    `json:"name,omitempty" db:"name"`
	Email            string    `json:"email,omitempty" db:"email"`
	Owner            string    `json:"owner,omitempty" db:"owner"`
	PublicKey        []byte    `json:"publicKey,omitempty" db:"public_key"`
	PrivateKey       []byte    `json:"privateKey,omitempty" db:"private_key"`
	CreationTime     time.Time `json:"creationTime,omitempty" db:"created_at"`
	LastModifiedTime time.Time `json:"lastModifiedTime,omitempty" db:"modified_at"`
}

func (entity *Identity) ToIdentityIdentifier() *api.IdentityIdentifier {

	rng := rand.Reader

	var s string
	s = entity.ID + entity.Email
	var message []byte = []byte(s)
	hashed := sha256.Sum256(message)

	signature, err := rsa.SignPKCS1v15(rng, entity.PrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return
	}

	return &api.IdentityIdentifier{
		Id:               entity.ID,
		Name:             entity.Name,
		ClientID:         "",
		Email:            entity.Email,
		PublicKey:        entity.PublicKey,
		Signature:        nil,
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
