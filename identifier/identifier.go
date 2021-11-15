package identifier

import (
	magnoliaApi "github.com/ory/hydra/pkg/magnolia/magnolia"
	"github.com/ory/hydra/subscription"
)

type Identifier struct {
	ID               string                        `json:"-"`
	Name             string                        `json:"name,omitempty"`
	DataAddress      string                        `json:"dataAddress,omitempty"`
	DataDigest       string                        `json:"dataDigest,omitempty"`
	DataSignature    []byte                        `json:"dataSignature,omitempty"`
	AuthAddress      string                        `json:"authAddress,omitempty"`
	Owner            string                        `json:"owner,omitempty"`
	Metadata         map[string]string             `json:"metadata,omitempty"`
	Tags             []string                      `json:"tags,omitempty"`
	SubscriptionType subscription.SubscriptionType `json:"subscriptionType,omitempty"`
}

func (entity *Identifier) ToDataIdentifier() *magnoliaApi.DataIdentifier {
	subscriptionType := magnoliaApi.SubscriptionType_Free
	if entity.SubscriptionType == subscription.Charged {
		subscriptionType = magnoliaApi.SubscriptionType_Charged
	}
	return &magnoliaApi.DataIdentifier{
		Id:               entity.Name,
		Name:             entity.Name,
		DataAddress:      entity.DataAddress,
		DataDigest:       entity.DataDigest,
		DataSignature:    entity.DataSignature,
		AuthAddress:      entity.AuthAddress,
		Owner:            entity.Owner,
		Metadata:         entity.Metadata,
		Tags:             entity.Tags,
		SubscriptionType: subscriptionType,
	}
}

func FromDataIdentifier(source *magnoliaApi.DataIdentifier) *Identifier {
	if source == nil {
		return nil
	}
	entity := &Identifier{}
	subscriptionType := subscription.Free
	if source.SubscriptionType == magnoliaApi.SubscriptionType_Charged {
		subscriptionType = subscription.Charged
	}
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
