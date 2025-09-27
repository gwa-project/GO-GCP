package route

import (
	"net/http"
	"strings"

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
	case method == "GET" && path == "/config":
		controller.GetConfig(w, r)
	case method == "GET" && path == "/data/user":
		controller.GetDataUser(w, r)

	// Authentication endpoints
	case method == "POST" && path == "/auth/login":
		controller.Login(w, r)
	case method == "POST" && path == "/auth/register":
		controller.Register(w, r)
	case method == "POST" && path == "/auth/refresh":
		controller.RefreshToken(w, r)
	case method == "GET" && path == "/auth/profile":
		controller.GetProfile(w, r)
	case method == "POST" && path == "/logout":
		controller.Logout(w, r)

	// User profile endpoints
	case method == "PUT" && path == "/profile/update":
		controller.UpdateProfile(w, r)
	case method == "PUT" && path == "/change-password":
		controller.ChangePassword(w, r)

	// Admin endpoints - User management
	case method == "GET" && path == "/admin/users":
		controller.GetAllUsers(w, r)
	case method == "POST" && path == "/admin/users":
		controller.CreateUser(w, r)
	case method == "GET" && strings.HasPrefix(path, "/admin/users/") && len(strings.Split(path, "/")) == 4:
		controller.GetUserByID(w, r)
	case method == "PUT" && strings.HasPrefix(path, "/admin/users/") && len(strings.Split(path, "/")) == 4:
		controller.UpdateUser(w, r)
	case method == "DELETE" && strings.HasPrefix(path, "/admin/users/") && len(strings.Split(path, "/")) == 4:
		controller.DeleteUser(w, r)

	// Legacy endpoint (for backward compatibility)
	case method == "GET" && path == "/users":
		controller.GetAllUsers(w, r)

	default:
		controller.NotFound(w, r)
	}
}