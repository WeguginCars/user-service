package handler

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"wegugin/api/auth"
	"wegugin/api/email"
	pb "wegugin/genproto/user"
	"wegugin/storage/redis"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Register godoc
// @Summary Register user
// @Description create new users
// @Tags auth
// @Param info body user.RegisterReq true "User info"
// @Success 200 {object} user.RegisterRes
// @Failure 400 {object} string "Invalid data"
// @Failure 500 {object} string "Server error"
// @Router /auth/register [post]
func (h Handler) Register(c *gin.Context) {
	h.Log.Info("Register is starting")
	req := pb.RegisterReq{}
	if err := c.BindJSON(&req); err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !email.IsValidEmail(req.Email) {
		h.Log.Error("Invalid email")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email"})
		return
	}
	res, err := h.User.Register(c, &req)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	h.Log.Info("Register ended")
	c.JSON(http.StatusOK, gin.H{
		"Token": res.Token,
	})
}

// Login godoc
// @Summary login user
// @Description it generates new access and refresh tokens
// @Tags auth
// @Param userinfo body user.LoginReq true "username and password"
// @Success 200 {object} string "tokens"
// @Failure 400 {object} string "Invalid date"
// @Failure 500 {object} string "error while reading from server"
// @Router /auth/login [post]
func (h Handler) Login(c *gin.Context) {
	h.Log.Info("Login is working")
	req := pb.LoginReq{}

	if err := c.BindJSON(&req); err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	res, err := h.User.Login(c, &req)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	h.Log.Info("login is succesfully ended")
	c.JSON(http.StatusOK, gin.H{
		"Token": res.Token,
	})
}

// ForgotPassword godoc
// @Summary Forgot Password
// @Description it send code to your email address
// @Tags auth
// @Param token body user.GetUSerByEmailReq true "enough"
// @Success 200 {object} string "message"
// @Failure 400 {object} string "Invalid date"
// @Failure 500 {object} string "error while reading from server"
// @Router /auth/forgot-password [post]
func (h Handler) ForgotPassword(c *gin.Context) {
	h.Log.Info("ForgotPassword is working")
	var req pb.GetUSerByEmailReq
	if err := c.BindJSON(&req); err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	res, err := email.EmailCode(req.Email)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error sending email"})
		return
	}
	err = redis.StoreCodes(c, res, req.Email)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error storing codes in Redis"})
		return
	}
	h.Log.Info("ForgotPassword succeeded")
	c.JSON(200, gin.H{"message": "Password reset code sent to your email"})

}

// ResetPassword godoc
// @Summary Reset Password
// @Description it Reset your Password
// @Tags auth
// @Param token body user.ResetPassReq true "enough"
// @Success 200 {object} string "message"
// @Failure 400 {object} string "Invalid date"
// @Failure 500 {object} string "error while reading from server"
// @Router /auth/reset-password [post]
func (h *Handler) ResetPassword(c *gin.Context) {
	h.Log.Info("ResetPassword is working")
	var req pb.ResetPassReq
	if err := c.BindJSON(&req); err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	code, err := redis.GetCodes(c, req.Email)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusNotFound, gin.H{"error": err})
		return
	}
	if code != req.Code {
		h.Log.Error("Invalid code")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid code"})
		return
	}
	res, err := h.User.GetUSerByEmail(c, &pb.GetUSerByEmailReq{Email: req.Email})
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	_, err = h.User.UpdatePassword(c, &pb.UpdatePasswordReq{Id: res.Id, Password: req.Password})
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating password"})
		return
	}
	c.JSON(200, gin.H{"message": "Password reset successfully"})
}

// GetUserProfile godoc
// @Security ApiKeyAuth
// @Summary Get User Profile
// @Description Get User Profile by token
// @Tags user
// @Success 200 {object} user.GetUserResponse
// @Failure 400 {object} string "Invalid date"
// @Failure 500 {object} string "error while reading from server"
// @Router /user/profile [get]
func (h Handler) GetUserProfile(c *gin.Context) {
	h.Log.Info("GetUserProfile is working")
	token := c.GetHeader("Authorization")
	id, _, err := auth.GetUserIdFromToken(token)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	res, err := h.User.GetUserById(c, &pb.UserId{Id: id})
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting user"})
		return
	}
	h.Log.Info("GetUserProfile successful finished")
	c.JSON(200, res)
}

// UpdateUserProfile godoc
// @Security ApiKeyAuth
// @Summary Update User Profile
// @Description Update User Profile by token
// @Tags user
// @Param userinfo body user.UpdateUserRequest true "all"
// @Success 200 {object} string "message"
// @Failure 400 {object} string "Invalid date"
// @Failure 500 {object} string "error while reading from server"
// @Router /user/profile [put]
func (h Handler) UpdateUserProfile(c *gin.Context) {
	h.Log.Info("UpdateUserProfile is working")
	token := c.GetHeader("Authorization")
	id, _, err := auth.GetUserIdFromToken(token)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var user pb.UpdateUserRequest
	if err := c.BindJSON(&user); err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user.Id = id
	_, err = h.User.UpdateUser(c, &user)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating user"})
		return
	}
	h.Log.Info("User updated successfully finished")
	c.JSON(200, gin.H{"message": "User updated successfully"})
}

// ChangePassword godoc
// @Security ApiKeyAuth
// @Summary Update User Profile
// @Description Update User Profile by token
// @Tags user
// @Param userinfo body user.ResetPasswordReq true "all"
// @Success 200 {object} string "message"
// @Failure 400 {object} string "Invalid date"
// @Failure 500 {object} string "error while reading from server"
// @Router /user/change-password [post]
func (h Handler) ChangePassword(c *gin.Context) {
	h.Log.Info("ChangePassword is working")
	token := c.GetHeader("Authorization")
	id, _, err := auth.GetUserIdFromToken(token)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var user pb.ResetPasswordReq
	if err := c.BindJSON(&user); err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user.Id = id
	_, err = h.User.ResetPassword(c, &user)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error resetting password"})
		return
	}
	h.Log.Info("Password changed successfully finished")
	c.JSON(200, gin.H{"message": "Password changed successfully"})
}

// @Summary UploadMediaUser
// @Security ApiKeyAuth
// @Description Api for upload a new photo
// @Tags user
// @Accept multipart/form-data
// @Param file formData file true "UploadMediaForm"
// @Success 200 {object} string
// @Failure 400 {object} string
// @Failure 500 {object} string
// @Router /user/photo [post]
func (h *Handler) UploadMediaUser(c *gin.Context) {
	h.Log.Info("UploadMediaUser started")
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Error retrieving the file"})
		return
	}
	defer file.Close()

	// minio start

	fileExt := filepath.Ext(header.Filename)
	println("\n File Ext:", fileExt)

	newFile := uuid.NewString() + fileExt
	minioClient, err := minio.New("localhost:9000", &minio.Options{
		Creds:  credentials.NewStaticV4("test", "minioadmin", ""),
		Secure: false,
	})
	if err != nil {
		c.AbortWithError(500, err)
		return
	}

	info, err := minioClient.PutObject(context.Background(), "photos", newFile, file, header.Size, minio.PutObjectOptions{
		ContentType: "image/jpeg",
	})
	if err != nil {
		c.AbortWithError(500, err)
		return
	}

	policy := fmt.Sprintf(`{
	 "Version": "2012-10-17",
	 "Statement": [
	  {
	   "Effect": "Allow",
	   "Principal": {
		"AWS": ["*"]
	   },
	   "Action": ["s3:GetObject"],
	   "Resource": ["arn:aws:s3:::%s/*"]
	  }
	 ]
	}`, "photos")

	err = minioClient.SetBucketPolicy(context.Background(), "photos", policy)
	if err != nil {
		c.AbortWithError(500, err)
		return
	}

	madeUrl := fmt.Sprintf("http://localhost:9000/photos/%s", newFile)

	println("\n Info Bucket:", info.Bucket)

	// minio end
	token := c.GetHeader("Authorization")
	id, _, err := auth.GetUserIdFromToken(token)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	reqmain := pb.UpdateUserRequest{Id: id, Photo: madeUrl}
	_, err = h.User.UpdateUser(c, &reqmain)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating user"})
		return
	}
	h.Log.Info("UploadMediaUser finished successfully")
	c.JSON(200, gin.H{
		"minio url": madeUrl,
	})

}
