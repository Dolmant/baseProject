package authhandlers

import (
	"fmt"
	"net/http"

	"bitbucket.org/Dolmant/gold/auth-service/pb"
	"bitbucket.org/Dolmant/gold/auth-service/pkg/auth/service"
	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	authService authservice.Service
}

func NewHandlers(authService authservice.Service) UserHandler {
	return UserHandler{authService: authService}
}

func (ctrl UserHandler) Login(c *gin.Context) {
	var json pb.LoginRequest
	err := c.BindQuery(&json)
	fmt.Println(json)
	if err != nil {
		fmt.Println(err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Malformed Request"})
		return
	}

	reply, err := ctrl.authService.Login(&json)
	if err != nil {
		fmt.Println(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal Error"})
		return
	}
	c.JSON(http.StatusOK, reply)
}

func (ctrl UserHandler) Subscribe(c *gin.Context) {
	var json pb.SubscribeRequest
	err := c.BindQuery(&json)
	if err != nil {
		fmt.Println(err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Malformed Request"})
		return
	}
	// Not required, middleware aborts early but still a good idea to check:
	authData := c.MustGet("JWTPayload").(pb.JWTPayloadType) // ensures auth
	json.JWTPayload = &authData

	reply, err := ctrl.authService.Subscribe(&json)
	if err != nil {
		fmt.Println(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal Error"})
		return
	}

	c.JSON(http.StatusOK, reply)
}

func (ctrl UserHandler) UnSubscribe(c *gin.Context) {
	var json pb.UnSubscribeRequest
	err := c.BindQuery(&json)
	if err != nil {
		fmt.Println(err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Malformed Request"})
		return
	}
	// todo this should be a wrapper function
	// Not required, middleware aborts early but still a good idea to check:
	authData := c.MustGet("JWTPayload").(pb.JWTPayloadType) // ensures auth
	json.JWTPayload = &authData

	reply, err := ctrl.authService.UnSubscribe(&json)
	if err != nil {
		fmt.Println(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal Error"})
		return
	}

	c.JSON(http.StatusOK, reply)
}

func (ctrl UserHandler) NewUser(c *gin.Context) {
	var json pb.NewUserRequest
	err := c.BindQuery(&json)
	fmt.Println(json)
	if err != nil {
		fmt.Println(err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Malformed Request"})
		return
	}

	reply, err := ctrl.authService.NewUser(&json)
	if err != nil {
		fmt.Println(err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal Error"})
		return
	}
	c.JSON(http.StatusOK, reply)
}
