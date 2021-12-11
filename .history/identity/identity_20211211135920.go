package identity

import (
	"time"

	"github.com/fuxi-inc/magnolia/pkg/api"
)

// type Identity struct {
// 	ID               string    `json:"id,omitempty"`
// 	Name             string    `json:"name,omitempty"`
// 	ClientID         string    `json:"clientID,omitempty"`
// 	Email            string    `json:"email,omitempty"`
// 	PublicKey        []byte    `json:"publicKey,omitempty"`
// 	Signature        []byte    `json:"signature,omitempty"`
// 	CreationTime     time.Time `json:"creationTime,omitempty"`
// 	LastModifiedTime time.Time `json:"lastModifiedTime,omitempty"`
// }

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

// func (entity *Identity) ToIdentityIdentifier() *api.IdentityIdentifier {
// 	return &api.IdentityIdentifier{
// 		Id:               entity.ID,
// 		Name:             entity.Name,
// 		ClientID:         entity.ClientID,
// 		Email:            entity.Email,
// 		PublicKey:        entity.PublicKey,
// 		Signature:        entity.Signature,
// 		CreationTime:     entity.CreationTime,
// 		LastModifiedTime: entity.LastModifiedTime,
// 	}
// }

func (entity *Identity) ToIdentityIdentifier() *api.IdentityIdentifier {
	return &api.IdentityIdentifier{
		Id:               entity.ID,
		Name:             entity.Name,
		Email:            entity.Email,
		PublicKey:        entity.PublicKey,
		Signature:        entity.Signature,
		CreationTime:     entity.CreationTime,
		LastModifiedTime: entity.LastModifiedTime,
	}
}

// func FromIdentityIdentifier(source *api.IdentityIdentifier) *Identity {
// 	if source == nil {
// 		return nil
// 	}

// 	entity := &Identity{}
// 	entity.ID = source.GetId()
// 	entity.Name = source.GetName()
// 	entity.ClientID = source.GetClientID()
// 	entity.Email = source.GetEmail()
// 	entity.PublicKey = source.GetPublicKey()
// 	entity.Signature = source.GetSignature()
// 	entity.CreationTime = source.GetCreationTime()
// 	entity.LastModifiedTime = source.GetLastModifiedTime()
// 	return entity

// }

func FromIdentityIdentifier(source *api.IdentityIdentifier) *Identity {
	if source == nil {
		return nil
	}

	entity := &Identity{}
	entity.ID = source.GetId()
	entity.Name = source.GetName()
	entity.ClientID = source.GetClientID()
	entity.Email = source.GetEmail()
	entity.PublicKey = source.GetPublicKey()
	entity.Signature = source.GetSignature()
	entity.CreationTime = source.GetCreationTime()
	entity.LastModifiedTime = source.GetLastModifiedTime()
	return entity

}
