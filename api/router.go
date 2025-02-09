package api

import (
	_ "wegugin/api/docs"
	"wegugin/api/handler"
	"wegugin/api/middleware"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
// @title User
// @version 1.0
// @description API Gateway
// BasePath: /
func Router(hand *handler.Handler) *gin.Engine {
	router := gin.Default()
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	auth := router.Group("/auth")
	{
		auth.POST("/register", hand.Register)
		auth.POST("/login", hand.Login)
		auth.POST("/forgot-password", hand.ForgotPassword)
		auth.POST("/reset-password", hand.ResetPassword)
	}

	user := router.Group("/user")
	user.Use(middleware.Check)
	{
		user.GET("/profile", hand.GetUserProfile)
		user.PUT("/profile", hand.UpdateUserProfile)
		user.POST("/change-password", hand.ChangePassword)
		user.POST("/photo", hand.UploadMediaUser)
		user.DELETE("/photo", hand.DeleteMediaUser)

	}
	return router
}
