package subscription

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
	"github.com/ory/herodot"
	"github.com/ory/hydra/driver/config"
	"github.com/ory/hydra/internal/logger"
	"github.com/ory/hydra/x"
	"github.com/ory/x/errorsx"
	"github.com/ory/x/pagination"
	"go.uber.org/zap"
)

type Handler struct {
	r InternalRegistry
	c *config.Provider
}

const (
	SubscriptionHandlerPath = "/subscriptions"
)

func NewHandler(r InternalRegistry, c *config.Provider) *Handler {
	return &Handler{
		r: r,
		c: c,
	}
}

func (h *Handler) SetRoutes(public *x.RouterPublic) {
	public.POST(SubscriptionHandlerPath, h.Create)
	public.GET(SubscriptionHandlerPath+"/:id", h.Get)
	public.DELETE(SubscriptionHandlerPath+"/:id", h.Delete)
	public.PATCH(SubscriptionHandlerPath+"/:id", h.Audit)
	public.GET(SubscriptionHandlerPath, h.List)
}

// swagger:parameters createSubscription
type createSubscription struct {
	// in:body
	Body struct {
		Apikey     string `json:"Authorization"`
		Identifier string `json:"identifier"`
		Recipient  string `json:"recipient"`
	}
}

// Subscription information response are sent when the operation succeeds.
// swagger:response subscriptionResp
type subscriptionResp struct {
	// in:body
	Body Subscription
}

// swagger:route POST /subscriptions subscription createSubscription
//
// Create a data identifier subscription
//
// Create a new data identifier subscription if you have the valid license(apiKey). The privateKey and publicKey are returned in response.
//
//
//     Consumes:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Produces:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Schemes: http, https
//
//     Responses:
//       200: subscriptionResp
// 		 400: jsonError
//       404: jsonError
//       500: jsonError
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

	ctx := context.WithValue(context.TODO(), "apiKey", accessToken)

	err := h.r.SubscriptionManager().CreateSubscriptionOwner(ctx, &entity)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	entity.init()

	err = h.r.SubscriptionManager().CreateSubscription(ctx, &entity)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	if entity.Recipient == entity.Owner {
		// if shared subscription
		approveResult := &ApproveResult{
			Status: Granted,
		}
		h.audit(w, r, &entity, approveResult)
	} else {
		h.r.Writer().WriteCreated(w, r, SubscriptionHandlerPath+"/"+entity.ID, &entity)
	}
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

// the ID of data subscription
// swagger:parameters dataIdentifierID
type dataSubscriptionID struct {
	// in: path
	Id string `json:"id"`
}

// swagger:route GET /subscriptions/{id} subscription dataSubscriptionID
//
// Get the data identifier subscription
//
// Get the data identifier subscription with the subscriptionID.
//
//
//     Consumes:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Produces:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Schemes: http, https
//
//     Responses:
//       200: subscriptionResp
// 		 400: jsonError
//       404: jsonError
//       500: jsonError
func (h *Handler) Get(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")
	subject := r.URL.Query().Get("identity")

	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New("no token provided"))
		return
	}

	ctx := context.WithValue(context.TODO(), "apiKey", accessToken)
	entity, err := h.r.SubscriptionManager().GetSubscription(ctx, id, subject)
	if err != nil {
		err = herodot.ErrUnauthorized.WithReason("The requested subscription does not exist or you did not provide the necessary credentials")
		h.r.Writer().WriteError(w, r, err)
		return
	}
	if entity == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if strings.Compare(subject, entity.Requestor) == 0 || strings.Compare(subject, entity.Owner) == 0 {
		h.r.Writer().Write(w, r, entity)
		return
	}
	logger.Get().Infow("unauthorized", zap.String("subject", subject), zap.Any("subscription", entity))
	w.WriteHeader(http.StatusUnauthorized)
}

// swagger:route DELETE /subscriptions/{id} subscription dataSubscriptionID
//
// Delete the data identifier subscription
//
// Delete the data identifier subscription with the subscriptionID.
//
//
//     Consumes:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Produces:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Schemes: http, https
//
//     Responses:
//       200: jsonError
// 		 400: jsonError
//       404: jsonError
//       500: jsonError
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")
	subject := r.URL.Query().Get("identity")

	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New("no token provided"))
		return
	}

	ctx := context.WithValue(context.TODO(), "apiKey", accessToken)
	entity, err := h.r.SubscriptionManager().GetSubscription(ctx, id, subject)
	if err != nil {
		h.r.Writer().WriteError(w, r, errors.New("load entity failed"))
		return
	}
	if entity == nil {
		h.r.Writer().WriteError(w, r, errors.New("no entity exists"))
		return
	}

	if subject != entity.Requestor {
		h.r.Writer().WriteError(w, r, errors.New("no permission"))
		return
	}

	if entity.Status != Applied {
		h.r.Writer().WriteError(w, r, errors.New("illegal status"))
		return
	}

	if err = h.r.SubscriptionManager().DeleteSubscription(ctx, id, subject); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	accessToken := fosite.AccessTokenFromRequest(r)
	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New("no token provided"))
		return
	}

	subject := r.URL.Query().Get("identity")

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
	subject := r.URL.Query().Get("identity")
	entity, err := h.r.SubscriptionManager().GetSubscription(r.Context(), id, subject)
	if err != nil {
		logger.Get().Info(zap.Error(err))
		h.r.Writer().WriteError(w, r, errors.New("load entity failed"))
		return
	}
	if entity == nil {
		h.r.Writer().WriteError(w, r, errors.New("no entity exists"))
		return
	}
	if !entity.IsActive() {
		h.r.Writer().WriteError(w, r, errors.New("wrong status"))
		return
	}

	accessToken := fosite.AccessTokenFromRequest(r)

	if accessToken == "" {
		h.r.Writer().WriteError(w, r, errors.New("no token provided"))
		return
	}

	// _, err = h.r.AccessTokenJWTStrategy().Validate(context.TODO(), accessToken)
	// if err != nil {
	// 	h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
	// 	return
	// }

	// token, err := h.r.AccessTokenJWTStrategy().Decode(r.Context(), accessToken)
	// if err != nil {
	// 	h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
	// 	return
	// }
	// subject := token.Claims["sub"].(string)
	if subject != entity.Owner {
		h.r.Writer().WriteError(w, r, errors.New("no permission"))
		return
	}

	var approveResult ApproveResult

	if err := json.NewDecoder(r.Body).Decode(&approveResult); err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}

	logger.Get().Infow("ready to audit the subscription", zap.Any("action", approveResult))
	h.audit(w, r, entity, &approveResult)
}

func (h *Handler) logOrAudit(err error, r *http.Request) {
	if errors.Is(err, fosite.ErrServerError) || errors.Is(err, fosite.ErrTemporarilyUnavailable) || errors.Is(err, fosite.ErrMisconfiguration) {
		x.LogError(r, err, h.r.Logger())
	} else {
		x.LogAudit(r, err, h.r.Logger())
	}
}

// swagger:parameters auditSubscription
type auditSubscription struct {
	// in: path
	Id string `json:"id"`
	// in:body
	Body struct {
		Status string `json:"status"`
	}
}

// swagger:route PATCH /subscriptions/{id} subscription auditSubscription
//
// Audit the data identifier subscription
//
// Audit the data identifier subscription with the subscriptionID.
//
//
//     Consumes:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Produces:
//     - application/json
//     - application/x-www-form-urlencoded
//
//     Schemes: http, https
//
//     Responses:
//       200: subscriptionResp
// 		 400: jsonError
//       404: jsonError
//       500: jsonError
func (h *Handler) audit(w http.ResponseWriter, r *http.Request, entity *Subscription, approveResult *ApproveResult) {
	// Generate the access token
	now := time.Now().UTC()
	claim := &jwt.JWTClaims{
		Subject:    entity.Owner,
		Issuer:     "ORY Hydra",
		Audience:   []string{entity.Recipient},
		IssuedAt:   now,
		ExpiresAt:  now.Add(time.Duration(259200) * time.Second),
		Scope:      []string{entity.Identifier},
		Extra:      map[string]interface{}{"requestor": entity.Requestor, "subscription": entity.ID},
		ScopeField: 0,
	}
	header := &jwt.Headers{}
	rawToken, _, err := h.r.AccessTokenJWTStrategy().Generate(context.TODO(), claim.ToMapClaims(), header)
	if err != nil {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}
	logger.Get().Infow("token", zap.Any("claim", claim.ToMapClaims()), zap.String("token", rawToken))

	entity.Content = rawToken
	err = h.r.SubscriptionManager().AuditSubscription(r.Context(), entity, approveResult)
	if err != nil {
		logger.Get().Infow("failed to audit subscription", zap.Error(err))
		h.r.Writer().WriteError(w, r, errorsx.WithStack(err))
		return
	}
	h.WriteAuditResponse(w, claim.ToMapClaims())
}

func (h *Handler) WriteAuditResponse(w http.ResponseWriter, claim jwt.MapClaims) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	js, err := json.Marshal(claim)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(js)
}