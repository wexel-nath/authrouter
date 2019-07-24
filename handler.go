package authrouter

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

type Handler func(r *http.Request, ps httprouter.Params, user User) (data interface{}, meta interface{}, status int)

func (router *Router) handle(handler Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		data, meta, status := handler(r, ps, User{})
		jsonResponse(w, data, meta, status)
	}
}

func (router *Router) handleWithAuthentication(handler Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		user, err := router.authenticator.Authenticate(r)
		if err != nil {
			notAuthenticatedResponse(w, err)
			return
		}

		data, meta, status := handler(r, ps, user)
		jsonResponse(w, data, meta, status)
	}
}

func (router *Router) handleWithAuthorization(
	handler Handler,
	service string,
	capability string,
) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		user, err := router.authenticator.Authorize(r, service, capability)
		if err != nil {
			notAuthenticatedResponse(w, err)
			return
		}

		data, meta, status := handler(r, ps, user)
		jsonResponse(w, data, meta, status)
	}
}
