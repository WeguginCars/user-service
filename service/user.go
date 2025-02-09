package service

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	pb "wegugin/genproto/user"
	"wegugin/storage"
	"wegugin/storage/postgres"
)

type UserService struct {
	pb.UnimplementedUserServer
	User   storage.IStorage
	Logger *slog.Logger
}

func NewUserService(db *sql.DB, Logger *slog.Logger) *UserService {
	return &UserService{
		User:   postgres.NewPostgresStorage(db),
		Logger: Logger,
	}
}

func (s *UserService) Register(ctx context.Context, req *pb.RegisterReq) (*pb.LoginRes, error) {
	s.Logger.Info("Register rpc methos is working")
	resp, err := s.User.User().CreateUser(ctx, req)
	if err != nil {
		s.Logger.Error(fmt.Sprintf("registration error: %v", err))
		return nil, err
	}
	s.Logger.Info("Register rpc method finished")
	return resp, nil
}

func (s *UserService) Login(ctx context.Context, req *pb.LoginReq) (*pb.LoginRes, error) {
	s.Logger.Info("Login rpc method is working")
	resp, err := s.User.User().Login(ctx, req)
	if err != nil {
		s.Logger.Error(fmt.Sprintf("login error: %v", err))
		return nil, err
	}
	s.Logger.Info("Login rpc method finished")
	return resp, nil
}

func (s *UserService) GetUSerByEmail(ctx context.Context, req *pb.GetUSerByEmailReq) (*pb.GetUserResponse, error) {
	s.Logger.Info("GetUSerByEmail rpc method is working")
	resp, err := s.User.User().GetUserByEmail(ctx, req)
	if err != nil {
		s.Logger.Error(fmt.Sprintf("Error retrieving email information: %v", err))
		return nil, err
	}
	s.Logger.Info("GetUSerByEmail rpc method finished")
	return resp, nil
}

func (s *UserService) GetUserById(ctx context.Context, req *pb.UserId) (*pb.GetUserResponse, error) {
	s.Logger.Info("GetUserById rpc method is working")
	resp, err := s.User.User().GetUserById(ctx, req)
	if err != nil {
		s.Logger.Error(fmt.Sprintf("Error retrieving id information: %v", err))
		return nil, err
	}
	s.Logger.Info("GetUserById rpc method finished")
	return resp, nil
}

func (s *UserService) UpdatePassword(ctx context.Context, req *pb.UpdatePasswordReq) (*pb.Void, error) {
	s.Logger.Info("UpdatePassword rpc method is working")
	err := s.User.User().UpdatePassword(ctx, req)
	if err != nil {
		s.Logger.Error(fmt.Sprintf("Error update pasword: %v", err))
		return nil, err
	}
	s.Logger.Info("UpdatePassword rpc method finished")
	return &pb.Void{}, nil
}

func (s *UserService) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.Void, error) {
	s.Logger.Info("UpdateUser rpc method is working")
	err := s.User.User().UpdateUser(ctx, req)
	if err != nil {
		s.Logger.Error(fmt.Sprintf("Error Update user: %v", err))
		return nil, err
	}
	s.Logger.Info("UpdateUser rpc method finished")
	return &pb.Void{}, nil
}

func (s *UserService) DeleteUser(ctx context.Context, req *pb.UserId) (*pb.Void, error) {
	s.Logger.Info("DeleteUser rpc method is working")
	err := s.User.User().DeleteUser(ctx, req)
	if err != nil {
		s.Logger.Error(fmt.Sprintf("error delete user: %v", err))
		return nil, err
	}
	s.Logger.Info("DeleteUser rpc method finished")
	return &pb.Void{}, nil
}

func (s *UserService) ResetPassword(ctx context.Context, req *pb.ResetPasswordReq) (*pb.Void, error) {
	s.Logger.Info("ResetPassword rpc method is working")
	err := s.User.User().ResetPassword(ctx, req)
	if err != nil {
		s.Logger.Error(fmt.Sprintf("error reset password: %v", err))
		return nil, err
	}
	s.Logger.Info("ResetPassword rpc method finished")
	return &pb.Void{}, nil
}

func (s *UserService) IsUserExist(ctx context.Context, req *pb.UserId) (*pb.Void, error) {
	s.Logger.Info("IsUserExist rpc method is working")
	err := s.User.User().IsUserExist(ctx, req)
	if err != nil {
		s.Logger.Error(fmt.Sprintf("error checking user existence: %v", err))
		return nil, err
	}
	s.Logger.Info("IsUserExist rpc method finished")
	return &pb.Void{}, nil
}

func (s *UserService) DeleteMediaUser(ctx context.Context, req *pb.UserId) (*pb.Void, error) {
	s.Logger.Info("DeleteMediaUser rpc method is working")
	err := s.User.User().DeleteMediaUser(ctx, req)
	if err != nil {
		s.Logger.Error(fmt.Sprintf("error deleting media user: %v", err))
		return nil, err
	}
	s.Logger.Info("DeleteMediaUser rpc method finished")
	return &pb.Void{}, nil
}
