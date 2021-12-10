package identity

import (
	"github.com/fuxi-inc/magnolia/pkg/api"
)

type Identity struct {
	ID               string `json:"-"`
	Name             string `json:"name,omitempty"`
	ClientID         string `json:"clientID,omitempty"`
	Email            string `json:"email,omitempty"`
	PublicKey        []byte `json:"publicKey,omitempty"`
	Signature        []byte `json:"signature,omitempty"`
	CreationTime     int64  `json:"creationTime,omitempty"`
	LastModifiedTime int64  `json:"lastModifiedTime,omitempty"`
}

func (entity *Identity) ToIdentityIdentifier() *api.IdentityIdentifier {
	return &api.IdentityIdentifier{
		Id:               entity.ID,
		Name:             entity.Name,
		ClientID:         entity.ClientID,
		Email:            entity.Email,
		PublicKey:        entity.PublicKey,
		Signature:        entity.Signature,
		CreationTime:     entity.CreationTime,
		LastModifiedTime: entity.LastModifiedTime,
	}
}

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
