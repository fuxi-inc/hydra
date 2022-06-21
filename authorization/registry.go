package authorization

import (
	"github.com/ory/fosite"
	"github.com/ory/hydra/jwk"
	"github.com/ory/hydra/x"
)

type InternalRegistry interface {
	x.RegistryLogger
	x.RegistryWriter
	Registry
}

type Registry interface {
	AuthorizationValidator() *Validator
	AuthorizationManager() Manager
	AccessTokenJWTStrategy() jwk.JWTStrategy
	OAuth2Provider() fosite.OAuth2Provider
}
