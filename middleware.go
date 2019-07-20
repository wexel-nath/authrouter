package authrouter

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func (router *Router) middleware(next httprouter.Handle) httprouter.Handle {
	next = router.loggerWrapper(next)
	next = router.corsMiddleware(next)
	return next
}

func (router *Router) loggerWrapper(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		router.Logger.Info("%s %s", r.Method, r.URL.Path)
		next(w, r, p)
	}
}

func (router *Router) corsMiddleware(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		next(w, r, p)
	}
}
