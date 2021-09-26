package identifier

import (
	"github.com/ory/hydra/jwk"
	"github.com/ory/hydra/x"
)

type InternalRegistry interface {
	x.RegistryWriter
	Registry
}

type Registry interface {
	IdentifierValidator() *Validator
	IdentifierManager() Manager
	AccessTokenJWTStrategy() jwk.JWTStrategy
}
