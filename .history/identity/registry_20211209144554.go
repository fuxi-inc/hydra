package identity

import (
	"github.com/ory/hydra/x"
)

type InternalRegistry interface {
	x.RegistryWriter
	Registry
}

type Registry interface {
	IdentityValidator() *Validator
	IdentityManager() Manager
}
