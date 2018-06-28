package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"

	"bitbucket.org/Dolmant/gold/auth-service/pb"
	"bitbucket.org/Dolmant/gold/auth-service/pkg/auth/service"

	"github.com/gin-gonic/gin"
)

func Authenticated(authService authservice.Service) gin.HandlerFunc {
	return func(c *gin.Context) {

		jwtToken := c.GetHeader("Authorization")

		if !authService.Validate(jwtToken) {
			fmt.Println("Not a valid token")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authorized"})
			return
		}

		payload, err := authService.Decrypt(jwtToken)
		if err != nil {
			fmt.Println(err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authorized"})
			return
		}

		jwtPayload := pb.JWTPayloadType{}

		err = json.Unmarshal([]byte(payload), &jwtPayload)

		if err != nil {
			fmt.Println(err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authorized"})
			return
		}

		c.Set("JWTPayload", jwtPayload)
	}
}
