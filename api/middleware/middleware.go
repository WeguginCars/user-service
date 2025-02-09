package middleware

import (
	"net/http"
	"wegugin/api/auth"

	"github.com/gin-gonic/gin"
)

func Check(c *gin.Context) {
	refreshToken := c.GetHeader("Authorization")

	if refreshToken == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "Authorization is required",
		})
		return
	}

	_, err := auth.ValidateToken(refreshToken)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid token provided",
		})
		return
	}

	c.Next()
}
