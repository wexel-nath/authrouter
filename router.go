package authrouter

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

type Authenticator interface {
	Authenticate(r *http.Request) (user interface{}, err error)
	Authorize(r *http.Request, service string, capability string) (user interface{}, err error)
}

type Router struct {
	HttpRouter    *httprouter.Router
	Authenticator Authenticator
}

type Handler func(r *http.Request) (data interface{}, meta interface{}, status int)

type HandlerWithUser func(
	r *http.Request,
	user interface{},
) (data interface{}, meta interface{}, status int)

func (router *Router) Handle(method string, path string, handler Handler) {
	router.HttpRouter.Handle(method, path, router.handle(handler))
}

func (router *Router) handle(handler Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		data, meta, status := handler(r)
		jsonResponse(w, data, meta, status)
	}
}

func (router *Router) HandleWithAuthentication(method string, path string, handler HandlerWithUser) {
	router.HttpRouter.Handle(method, path, router.handleWithAuthentication(handler))
}

func (router *Router) handleWithAuthentication(handler HandlerWithUser) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		user, err := router.Authenticator.Authenticate(r)
		if err != nil {
			notAuthenticatedResponse(w, err)
			return
		}

		data, meta, status := handler(r, user)
		jsonResponse(w, data, meta, status)
	}
}

func (router *Router) HandleWithAuthorization(
	method string,
	path string,
	handler HandlerWithUser,
	service string,
	capability string,
) {
	router.HttpRouter.Handle(
		method,
		path,
		router.handleWithAuthorization(handler, service, capability),
	)
}

func (router *Router) handleWithAuthorization(
	handler HandlerWithUser,
	service string,
	capability string,
) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		user, err := router.Authenticator.Authorize(r, service, capability)
		if err != nil {
			notAuthenticatedResponse(w, err)
			return
		}

		data, meta, status := handler(r, user)
		jsonResponse(w, data, meta, status)
	}
}
