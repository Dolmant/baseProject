package authmodels

type User struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Password string `json:"password"`
}
