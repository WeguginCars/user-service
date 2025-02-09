package model

type UpdateUser struct {
	Name        string `json:"name,omitempty"`
	Surname     string `json:"surname,omitempty"`
	BirthDate   string `json:"birth_date,omitempty"`
	Gender      string `json:"gender,omitempty"`
	Address     string `json:"address,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
}

type ResetPassword struct {
	NewPassword string `json:"new_password,omitempty"`
	OldPassword string `json:"old_password,omitempty"`
}
