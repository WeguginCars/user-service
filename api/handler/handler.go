package handler

import (
	"log/slog"
	"wegugin/genproto/user"
)

type Handler struct {
	User user.UserClient
	Log  *slog.Logger
}
