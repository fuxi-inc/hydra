package identifier

import (
	"github.com/fuxi-inc/magnolia/pkg/api"
	"github.com/ory/hydra/subscription"
)

type Identifier struct {
	ID               string                        `json:"id,omitempty"`
	Name             string                        `json:"name,omitempty"`
	DataAddress      string                        `json:"dataAddress,omitempty"`
	DataDigest       string                        `json:"dataDigest,omitempty"`
	DataSignature    []byte                        `json:"dataSignature,omitempty"`
	AuthAddress      string                        `json:"authAddress,omitempty"`
	Owner            string                        `json:"owner,omitempty"`
	CategoryID       string                        `json:"categoryID,omitempty"`
	Metadata         map[string]string             `json:"metadata,omitempty"`
	Tags             []string                      `json:"tags,omitempty"`
	SubscriptionType subscription.SubscriptionType `json:"subscriptionType,omitempty"`
}

func (entity *Identifier) ToDataIdentifier() *api.DataIdentifier {
	return &api.DataIdentifier{
		Id:            entity.ID,
		Name:          entity.Name,
		DataAddress:   entity.DataAddress,
		DataDigest:    entity.DataDigest,
		DataSignature: entity.DataSignature,
		AuthAddress:   entity.AuthAddress,
		Owner:         entity.Owner,
		CategoryID
		Metadata:      entity.Metadata,
		Tags:          entity.Tags,
	}
}

func FromDataIdentifier(source *api.DataIdentifier) *Identifier {
	if source == nil {
		return nil
	}
	entity := &Identifier{}
	subscriptionType := subscription.Free
	entity.ID = source.GetId()
	entity.Name = source.GetName()
	entity.DataAddress = source.GetDataAddress()
	entity.DataDigest = source.GetDataDigest()
	entity.AuthAddress = source.GetAuthAddress()
	entity.Owner = source.GetOwner()
	entity.Metadata = source.GetMetadata()
	entity.Tags = source.GetTags()
	entity.SubscriptionType = subscriptionType
	return entity
}
