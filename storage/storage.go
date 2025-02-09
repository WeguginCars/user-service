package storage

import (
	"context"
	pb "wegugin/genproto/user"
)

type IStorage interface {
	User() IUserStorage
	Close()
}

type IUserStorage interface {
	CreateUser(context.Context, *pb.RegisterReq) (*pb.LoginRes, error)
	Login(context.Context, *pb.LoginReq) (*pb.LoginRes, error)
	GetUserByEmail(context.Context, *pb.GetUSerByEmailReq) (*pb.GetUserResponse, error)
	GetUserById(context.Context, *pb.UserId) (*pb.GetUserResponse, error)
	UpdatePassword(context.Context, *pb.UpdatePasswordReq) error
	UpdateUser(context.Context, *pb.UpdateUserRequest) error
	DeleteUser(context.Context, *pb.UserId) error
	ResetPassword(context.Context, *pb.ResetPasswordReq) error
	IsUserExist(context.Context, *pb.UserId) error
	DeleteMediaUser(context.Context, *pb.UserId) error
}
