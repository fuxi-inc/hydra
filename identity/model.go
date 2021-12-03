package identifier

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
		Id:               "",
		Name:             "",
		ClientID:         "",
		Email:            "",
		PublicKey:        nil,
		Signature:        nil,
		CreationTime:     0,
		LastModifiedTime: 0,
	}
}

func FromIdentityIdentifier(source *api.IdentityIdentifier) *Identity {
	if source == nil {
		return nil
	}

	return &Identity{
		ID:               "",
		Name:             "",
		ClientID:         "",
		Email:            "",
		PublicKey:        nil,
		Signature:        nil,
		CreationTime:     0,
		LastModifiedTime: 0,
	}
}
