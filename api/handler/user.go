package handler

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"wegugin/api/auth"
	"wegugin/api/email"
	"wegugin/config"
	pb "wegugin/genproto/user"
	"wegugin/model"
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
// @Success 200 {object} string "Token"
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
// @Success 200 {object} string "Token"
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.Log.Info("login is succesfully ended")
	c.JSON(http.StatusOK, gin.H{
		"Token": res.Token,
	})
}

// GetUserById godoc
// @Summary Get User By Id
// @Description Get User By Id
// @Tags auth
// @Param id path string true "USER ID"
// @Success 200 {object} user.GetUserResponse
// @Failure 400 {object} string "Invalid date"
// @Failure 500 {object} string "error while reading from server"
// @Router /auth/user/{id} [get]
func (h Handler) GetUserById(c *gin.Context) {
	h.Log.Info("GetUserById is working")
	id := c.Param("id")
	res, err := h.User.GetUserById(c, &pb.UserId{Id: id})
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.Log.Info("GetUserById succeeded")
	c.JSON(http.StatusOK, res)
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
// @Param userinfo body model.UpdateUser true "all"
// @Success 200 {object} string "User updated successfully"
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
	var user model.UpdateUser
	if err := c.BindJSON(&user); err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err = h.User.UpdateUser(c, &pb.UpdateUserRequest{
		Id:          id,
		Name:        user.Name,
		Surname:     user.Surname,
		BirthDate:   user.BirthDate,
		Gender:      user.Gender,
		Address:     user.Address,
		PhoneNumber: user.PhoneNumber,
	})
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
// @Param userinfo body model.ResetPassword true "all"
// @Success 200 {object} string "Password changed successfully"
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
	var user model.ResetPassword
	if err := c.BindJSON(&user); err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err = h.User.ResetPassword(c, &pb.ResetPasswordReq{
		Id:          id,
		Newpassword: user.NewPassword,
		Oldpassword: user.OldPassword,
	})
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
	cfg := config.Load()

	fileExt := filepath.Ext(header.Filename)

	newFile := uuid.NewString() + fileExt
	minioClient, err := minio.New(cfg.Minio.MINIO_ENDPOINT, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.Minio.MINIO_ACCESS_KEY_ID, cfg.Minio.MINIO_SECRET_ACCESS_KEY, ""),
		Secure: false,
	})
	if err != nil {
		c.AbortWithError(500, err)
		return
	}

	info, err := minioClient.PutObject(context.Background(), "photos", newFile, file, header.Size, minio.PutObjectOptions{
		ContentType: getContentType(fileExt),
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

	madeUrl := fmt.Sprintf("%s/photos/%s", cfg.Minio.MINIO_PUBLIC_URL, newFile)

	println("\n Info Bucket:", info.Bucket)

	// minio end
	token := c.GetHeader("Authorization")
	id, _, err := auth.GetUserIdFromToken(token)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	err = h.deletePhoto(id, c)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting user's photo"})
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

func getContentType(fileExt string) string {
	switch fileExt {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	default:
		return "application/octet-stream"
	}
}

// @Summary DeleteMediaUser
// @Security ApiKeyAuth
// @Description Api for deleting a user's photo
// @Tags user
// @Success 200 {object} string
// @Failure 400 {object} string
// @Failure 500 {object} string
// @Router /user/photo [delete]
func (h *Handler) DeleteMediaUser(c *gin.Context) {
	h.Log.Info("DeleteMediaUser started")

	// Tokenni olish va foydalanuvchi ID sini olish
	token := c.GetHeader("Authorization")
	id, _, err := auth.GetUserIdFromToken(token)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	err = h.deletePhoto(id, c)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting user's photo"})
		return
	}

	h.Log.Info("DeleteMediaUser finished successfully")
	c.JSON(200, gin.H{"message": "User photo deleted successfully"})
}

func (h *Handler) deletePhoto(id string, ctx context.Context) error {
	// Foydalanuvchi ma'lumotlarini olish
	user, err := h.User.GetUserById(ctx, &pb.UserId{Id: id})
	if err != nil {
		h.Log.Error(err.Error())
		return fmt.Errorf("error retrieving user data: %v", err)
	}

	// Foydalanuvchining joriy fotosi yo'qligini tekshirish
	if user.Photo == "" {
		h.Log.Error("User has no photo to delete")
		return nil
	}

	// MinIO clientni sozlash
	cfg := config.Load()
	minioClient, err := minio.New(cfg.Minio.MINIO_ENDPOINT, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.Minio.MINIO_ACCESS_KEY_ID, cfg.Minio.MINIO_SECRET_ACCESS_KEY, ""),
		Secure: false,
	})
	if err != nil {
		return fmt.Errorf("error initializing MinIO client: %v", err)
	}

	// Rasm nomini olish
	fileName := filepath.Base(user.Photo)

	// MinIO'dan faylni o‘chirish
	err = minioClient.RemoveObject(context.Background(), "photos", fileName, minio.RemoveObjectOptions{})
	if err != nil {
		h.Log.Error(err.Error())
		return fmt.Errorf("error deleting photo from MinIO: %v", err)
	}

	// Foydalanuvchining photo maydonini bo‘sh qilish
	_, err = h.User.DeleteMediaUser(ctx, &pb.UserId{
		Id: id,
	})
	if err != nil {
		h.Log.Error(err.Error())
		return fmt.Errorf("error updating user: %v", err)
	}
	return nil
}

// @Summary DeleteUserProfile
// @Security ApiKeyAuth
// @Description Api for deleting a user's profile
// @Tags user
// @Success 200 {object} string
// @Failure 400 {object} string
// @Failure 500 {object} string
// @Router /user/delete [delete]
func (h *Handler) DeleteUserProfile(c *gin.Context) {
	h.Log.Info("DeleteUserProfile started")
	// Tokenni olish va foydalanuvchi ID sini olish
	token := c.GetHeader("Authorization")
	id, _, err := auth.GetUserIdFromToken(token)
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	_, err = h.User.DeleteUser(c, &pb.UserId{Id: id})
	if err != nil {
		h.Log.Error(err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting user's profile"})
		return
	}

	h.Log.Info("DeleteUserProfile finished successfully")
	c.JSON(200, gin.H{"message": "User profile deleted successfully"})
}
