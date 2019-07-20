package authrouter

import (
	"encoding/json"
	"net/http"
)

type meta struct {
	Message string `json:"message"`
}

func buildMeta(message string) meta {
	return meta{
		Message: message,
	}
}

type response struct {
	Data interface{} `json:"data"`
	Meta interface{} `json:"meta"`
}

func newResponse(data interface{}, meta interface{}) response {
	return response{
		Data: data,
		Meta: meta,
	}
}

func jsonResponse(w http.ResponseWriter, data interface{}, meta interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	bytes, _ := json.Marshal(newResponse(data, meta))
	w.Write(bytes)
}

func notAuthenticatedResponse(w http.ResponseWriter, err error) {
	jsonResponse(w, nil, buildMeta(err.Error()), http.StatusUnauthorized)
}
