package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
	"github.com/ory/x/pagination"

	"github.com/ory/hydra/x"

	"github.com/julienschmidt/httprouter"
)

type Handler struct {
	r InternalRegistry
}

const (
	IdentityHandlerPath = "/identity"
)

func NewHandler(r InternalRegistry) *Handler {
	return &Handler{
		r: r,
	}
}

func (h *Handler) SetRoutes(public *x.RouterPublic) {
	public.POST(IdentityHandlerPath+"/:id", h.Create)
	public.GET(IdentityHandlerPath+"/:id", h.Get)
	public.DELETE(IdentityHandlerPath+"/:id", h.Delete)
	public.GET(IdentityHandlerPath, h.List)
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var entity Identity

	if err := json.NewDecoder(r.Body).Decode(&entity); err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}

	if err := h.r.IdentityValidator().Validate(&entity); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	var clientID = ps.ByName("id")
	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" || clientID == "" {
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
	fmt.Println(token)
	subject := token.Claims["sub"].(string)
	fmt.Println(subject)

	entity.CreationTime = time.Now().UTC().Round(time.Second)
	entity.LastModifiedTime = entity.CreationTime

	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	publickey := &privatekey.PublicKey

	//entity.PrivateKey = x509.MarshalPKCS1PrivateKey(privatekey)
	entity.PublicKey = x509.MarshalPKCS1PublicKey(publickey)

	err = h.r.IdentityManager().CreateIdentity(r.Context(), &entity)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().WriteCreated(w, r, IdentityHandlerPath+"/"+entity.ID, &entity)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

}

// swagger:parameters listOAuth2Clients
type Filter struct {
	Limit    int    `json:"limit"`
	Offset   int    `json:"offset"`
	ClientId string `json:"client_id"`
	Tag      string `json:"tag"`
	Metadata string `json:"metadata"`
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	limit, offset := pagination.Parse(r, 100, 0, 500)
	filters := Filter{
		Limit:    limit,
		Offset:   offset,
		ClientId: r.URL.Query().Get("client_id"),
		Tag:      r.URL.Query().Get("tag"),
		Metadata: r.URL.Query().Get("metadata"),
	}

	c, err := h.r.IdentityManager().GetIdentities(r.Context(), filters)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	// TODO should get real total count
	pagination.Header(w, r.URL, 10000, limit, offset)

	if c == nil {
		c = []*Identity{}
	}

	h.r.Writer().Write(w, r, c)
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")

	entity, err := h.r.IdentityManager().GetIdentity(r.Context(), id)
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

	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New(""))
		return
	}

	err := h.r.IdentityManager().DeleteIdentity(r.Context(), id)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
