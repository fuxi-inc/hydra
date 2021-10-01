package subscription

import (
	"github.com/ory/fosite"
	"net/http"
)

var ErrInvalidSubscription = &fosite.RFC6749Error{
	DescriptionField: "The value of one of the Subscription fields is invalid and the server has rejected this request.",
	ErrorField:       "invalid_subscription_parameter",
	CodeField:        http.StatusBadRequest,
}
