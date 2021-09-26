package identifier

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ory/fosite"
	"github.com/ory/herodot"
	"github.com/ory/hydra/internal/logger"
	"github.com/ory/hydra/pkg/magnolia"
	magolia_api "github.com/ory/hydra/pkg/magnolia/v1"
	"github.com/ory/x/errorsx"
	"net/http"

	"github.com/ory/hydra/x"

	"github.com/julienschmidt/httprouter"
)

type Handler struct {
	r InternalRegistry
}

const (
	IdentifierHandlerPath = "/identifiers"
)

func NewHandler(r InternalRegistry) *Handler {
	return &Handler{
		r: r,
	}
}

func (h *Handler) SetRoutes(public *x.RouterPublic) {
	public.POST(IdentifierHandlerPath, h.Create)
	public.GET(IdentifierHandlerPath+"/:id", h.Get)
	public.DELETE(IdentifierHandlerPath+"/:id", h.Delete)
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var entity magolia_api.DataIdentifier

	if err := json.NewDecoder(r.Body).Decode(&entity); err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}

	if err := h.r.IdentifierValidator().Validate(&entity); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New(""))
		return
	}

	_, err := h.r.AccessTokenJWTStrategy().Validate(context.TODO(), accessToken)
	if err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}

	token, err := h.r.AccessTokenJWTStrategy().Decode(r.Context(), accessToken)
	if err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}
	subject := token.Claims["sub"].(string)
	if subject != entity.Owner {
		h.r.Writer().WriteError(w, r, errors.New("no permission"))
		return
	}
	logger.Get().Infow("prepare to create data identifier")
	err = h.r.IdentifierManager().CreateIdentifier(r.Context(), &entity)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	logger.Get().Infow("create data identifier done")
	h.r.Writer().WriteCreated(w, r, IdentifierHandlerPath+"/"+entity.GetId(), &entity)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

}

// swagger:parameters listOAuth2Clients
type Filter struct {
	// The maximum amount of clients to returned, upper bound is 500 clients.
	// in: query
	Limit int `json:"limit"`

	// The offset from where to start looking.
	// in: query
	Offset int `json:"offset"`

	// The name of the clients to filter by.
	// in: query
	Name string `json:"client_name"`

	// The owner of the clients to filter by.
	// in: query
	Owner string `json:"owner"`
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")

	entity, err := h.r.IdentifierManager().GetIdentifier(r.Context(), id)
	if err != nil {
		err = herodot.ErrUnauthorized.WithReason("The requested OAuth 2.0 client does not exist or you did not provide the necessary credentials")
		h.r.Writer().WriteError(w, r, err)
		return
	}
	if entity == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	h.r.Writer().Write(w, r, entity)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")
	entity, err := h.r.IdentifierManager().GetIdentifier(r.Context(), id)
	if err != nil {
		h.r.Writer().WriteError(w, r, errors.New(""))
		return
	}
	if entity == nil {
		h.r.Writer().WriteError(w, r, errors.New(""))
		return
	}
	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New(""))
		return
	}

	_, err = h.r.AccessTokenJWTStrategy().Validate(context.TODO(), accessToken)
	if err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}

	token, err := h.r.AccessTokenJWTStrategy().Decode(r.Context(), accessToken)
	if err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}
	subject := token.Claims["sub"].(string)
	if subject != entity.Owner {
		h.r.Writer().WriteError(w, r, errors.New("no permission"))
		return
	}

	err = magnolia.DeleteIdentityIdentifier(id)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	if err = h.r.IdentifierManager().DeleteIdentifier(r.Context(), id); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}