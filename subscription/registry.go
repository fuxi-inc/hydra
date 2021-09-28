package subscription

import (
	"github.com/ory/hydra/jwk"
	"github.com/ory/hydra/x"
)

type InternalRegistry interface {
	x.RegistryWriter
	Registry
}

type Registry interface {
	SubscriptionValidator() *Validator
	SubscriptionManager() Manager
	AccessTokenJWTStrategy() jwk.JWTStrategy
}
