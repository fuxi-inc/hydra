package subscription

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/fosite"
	"github.com/ory/herodot"
	"github.com/ory/hydra/x"
	"github.com/ory/x/errorsx"
	"github.com/ory/x/pagination"
	"net/http"
)

type Handler struct {
	r InternalRegistry
}

const (
	SubscriptionHandlerPath = "/subscriptions"
)

func NewHandler(r InternalRegistry) *Handler {
	return &Handler{
		r: r,
	}
}

func (h *Handler) SetRoutes(public *x.RouterPublic) {
	public.POST(SubscriptionHandlerPath, h.Create)
	public.GET(SubscriptionHandlerPath+"/:id", h.Get)
	public.DELETE(SubscriptionHandlerPath+"/:id", h.Delete)
	public.PATCH(SubscriptionHandlerPath+"/:id", h.Audit)
	public.GET(SubscriptionHandlerPath, h.List)
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var entity Subscription

	if err := json.NewDecoder(r.Body).Decode(&entity); err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}

	if err := h.r.SubscriptionValidator().Validate(&entity); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	accessToken := fosite.AccessTokenFromRequest(r)
	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New("access token must be provided"))
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
	entity.Requestor = subject
	entity.init()

	err = h.r.SubscriptionManager().CreateSubscription(r.Context(), &entity)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().WriteCreated(w, r, SubscriptionHandlerPath+"/"+entity.ID, &entity)
}

type Filter struct {
	Limit     int    `json:"limit"`
	Offset    int    `json:"offset"`
	Name      string `json:"name"`
	Requestor string `json:"requestor"`
	Owner     string `json:"owner"`
	Status    string `json:"status"`
	Type      string `json:"type"`
	Role      string `json:"role"`
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")
	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New("no token provided"))
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

	entity, err := h.r.SubscriptionManager().GetSubscription(r.Context(), id)
	if err != nil {
		err = herodot.ErrUnauthorized.WithReason("The requested subscription does not exist or you did not provide the necessary credentials")
		h.r.Writer().WriteError(w, r, err)
		return
	}
	if entity == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if subject != entity.Requestor || subject != entity.Owner {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	h.r.Writer().Write(w, r, entity)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")
	entity, err := h.r.SubscriptionManager().GetSubscription(r.Context(), id)
	if err != nil {
		h.r.Writer().WriteError(w, r, errors.New("load entity failed"))
		return
	}
	if entity == nil {
		h.r.Writer().WriteError(w, r, errors.New("no entity exists"))
		return
	}
	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New("no token provided"))
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
	if subject != entity.Requestor {
		h.r.Writer().WriteError(w, r, errors.New("no permission"))
		return
	}

	if err = h.r.SubscriptionManager().DeleteSubscription(r.Context(), id); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	accessToken := fosite.AccessTokenFromRequest(r)
	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New("no token provided"))
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
	role := r.URL.Query().Get("role")
	if role == "" {
		h.r.Writer().WriteError(w, r, errors.New("no permission to query data"))
		return
	}

	var filters Filter
	limit, offset := pagination.Parse(r, 100, 0, 500)
	if role == "requestor" {
		filters = Filter{
			Limit:     limit,
			Offset:    offset,
			Requestor: subject,
			Status:    r.URL.Query().Get("status"),
			Type:      r.URL.Query().Get("type"),
		}
	} else {
		filters = Filter{
			Limit:  limit,
			Offset: offset,
			Owner:  subject,
			Status: r.URL.Query().Get("status"),
			Type:   r.URL.Query().Get("type"),
		}
	}

	totalCount, c, err := h.r.SubscriptionManager().GetSubscriptions(r.Context(), filters)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	pagination.Header(w, r.URL, totalCount, limit, offset)

	if c == nil {
		c = []Subscription{}
	}

	h.r.Writer().Write(w, r, c)
}

func (h *Handler) Audit(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")
	entity, err := h.r.SubscriptionManager().GetSubscription(r.Context(), id)
	if err != nil {
		h.r.Writer().WriteError(w, r, errors.New("load entity failed"))
		return
	}
	if entity == nil {
		h.r.Writer().WriteError(w, r, errors.New("no entity exists"))
		return
	}
	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New("no token provided"))
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

	var approveResult ApproveResult

	if err := json.NewDecoder(r.Body).Decode(&approveResult); err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}

	err = h.r.SubscriptionManager().AuditSubscription(r.Context(), &approveResult)
	if err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}
	w.WriteHeader(http.StatusOK)
}
