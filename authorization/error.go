package authorization

import (
	"github.com/ory/fosite"
	"net/http"
)

var ErrInvalidAuthorizationParams = &fosite.RFC6749Error{
	DescriptionField: "The value of one of the params fields is invalid and the server has rejected this request.",
	ErrorField:       "invalid_authorization_parameter",
	CodeField:        http.StatusBadRequest,
}

var ErrInvalidAuthorizationRequests = &fosite.RFC6749Error{
	DescriptionField: "The sign is invalid",
	ErrorField:       "invalid_signature",
	CodeField:        http.StatusForbidden,
}
