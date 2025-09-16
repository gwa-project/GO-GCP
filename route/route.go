package route

import (
	"net/http"

	"github.com/gocroot/config"
	"github.com/gocroot/controller"
)

func URL(w http.ResponseWriter, r *http.Request) {
	if config.SetAccessControlHeaders(w, r) {
		return // If it's a preflight request, return early.
	}
	config.SetEnv()

	var method, path string = r.Method, r.URL.Path

	switch {
	case method == "GET" && path == "/":
		controller.GetHome(w, r)
	case method == "GET" && path == "/health":
		controller.GetHealth(w, r)
	case method == "GET" && path == "/config":
		controller.GetConfig(w, r)
	case method == "GET" && path == "/data/user":
		controller.GetDataUser(w, r)
	case method == "POST" && path == "/data/user":
		controller.PostDataUser(w, r)
	case method == "PUT" && path == "/data/user":
		controller.PutDataUser(w, r)
	case method == "DELETE" && path == "/data/user":
		controller.DeleteDataUser(w, r)
	case method == "POST" && path == "/auth/login":
		controller.Login(w, r)
	case method == "POST" && path == "/auth/register":
		controller.Register(w, r)
	case method == "GET" && path == "/api/users":
		controller.GetAllUsers(w, r)
	default:
		controller.NotFound(w, r)
	}
}