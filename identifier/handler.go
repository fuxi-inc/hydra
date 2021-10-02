package identifier

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ory/fosite"
	magolia_api "github.com/ory/hydra/pkg/magnolia/v1"
	"github.com/ory/x/errorsx"
	"github.com/ory/x/pagination"
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
	public.GET(IdentifierHandlerPath, h.List)
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
	err = h.r.IdentifierManager().CreateIdentifier(r.Context(), &entity)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().WriteCreated(w, r, IdentifierHandlerPath+"/"+entity.GetId(), &entity)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

}

// swagger:parameters listOAuth2Clients
type Filter struct {
	Limit    int    `json:"limit"`
	Offset   int    `json:"offset"`
	ClientId string `json:"client_id"`
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	limit, offset := pagination.Parse(r, 100, 0, 500)
	filters := Filter{
		Limit:    limit,
		Offset:   offset,
		ClientId: r.URL.Query().Get("client_id"),
	}

	c, err := h.r.IdentifierManager().GetIdentifiers(r.Context(), filters)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	// TODO should get real total count
	pagination.Header(w, r.URL, 10000, limit, offset)

	if c == nil {
		c = []*magolia_api.DataIdentifier{}
	}

	h.r.Writer().Write(w, r, c)
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")

	entity, err := h.r.IdentifierManager().GetIdentifier(r.Context(), id)
	if err != nil {
		//err = herodot.ErrUnauthorized.WithReason("")
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
		h.r.Writer().WriteError(w, r, err)
		return
	}
	if entity == nil {
		h.r.Writer().WriteError(w, r, errors.New("notfound"))
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

	err = h.r.IdentifierManager().DeleteIdentifier(r.Context(), id)
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
