package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"wegugin/api/auth"
	pb "wegugin/genproto/user"
	"wegugin/storage"

	"golang.org/x/crypto/bcrypt"
)

type UserRepository struct {
	Db *sql.DB
}

func NewUserRepository(db *sql.DB) storage.IUserStorage {
	return &UserRepository{Db: db}
}

func (u UserRepository) CreateUser(ctx context.Context, req *pb.RegisterReq) (*pb.LoginRes, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	tx, err := u.Db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	var userID, userRole string
	userQuery := `INSERT INTO users (email, password_hash, phone_number)
                  VALUES ($1, $2, $3) RETURNING id, role`
	err = tx.QueryRowContext(ctx, userQuery, req.Email, string(hashedPassword), req.Phone).Scan(&userID, &userRole)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to insert user: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	token, err := auth.GenerateJWTToken(userID, userRole)
	if err != nil {
		return nil, fmt.Errorf("failed to generate jwt token: %w", err)
	}

	return &pb.LoginRes{
		Token: token,
	}, nil
}

func (u UserRepository) Login(ctx context.Context, req *pb.LoginReq) (*pb.LoginRes, error) {
	query := `SELECT id, password_hash , role FROM users WHERE email = $1 and deleted_at=0`

	var id, passwordHash, role string
	err := u.Db.QueryRowContext(ctx, query, req.EmailOrPhoneNumber).Scan(&id, &passwordHash, &role)
	if err != nil {
		if err == sql.ErrNoRows {
			query = `SELECT id, password_hash, role FROM users WHERE phone_number = $1`
			err = u.Db.QueryRowContext(ctx, query, req.EmailOrPhoneNumber).Scan(&id, &passwordHash, &role)
			if err != nil {
				if err == sql.ErrNoRows {
					return nil, errors.New("user not found")
				}
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return nil, fmt.Errorf("password is incorrect")
		}
		return nil, err
	}

	token, err := auth.GenerateJWTToken(id, role)
	if err != nil {
		return nil, fmt.Errorf("failed to generate jwt token: %w", err)
	}

	return &pb.LoginRes{
		Token: token,
	}, nil
}

func (u *UserRepository) GetUserByEmail(ctx context.Context, req *pb.GetUSerByEmailReq) (*pb.GetUserResponse, error) {
	query := `SELECT id, name, surname, email, birth_date, gender, phone_number, address, photo, role, created_at 
	          FROM users WHERE email = $1 AND deleted_at=0`

	var (
		user      pb.GetUserResponse
		name      sql.NullString
		surname   sql.NullString
		birthDate sql.NullTime
		gender    sql.NullString
		address   sql.NullString
		photo     sql.NullString
	)

	err := u.Db.QueryRowContext(ctx, query, req.Email).Scan(
		&user.Id, &name, &surname, &user.Email,
		&birthDate, &gender, &user.PhoneNumber,
		&address, &photo, &user.Role, &user.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	// NULL bo'lishi mumkin bo'lgan maydonlarni tekshirish
	user.Name = name.String
	if !name.Valid {
		user.Name = ""
	}

	user.Surname = surname.String
	if !surname.Valid {
		user.Surname = ""
	}

	user.Gender = gender.String
	if !gender.Valid {
		user.Gender = ""
	}

	user.Address = address.String
	if !address.Valid {
		user.Address = ""
	}

	user.Photo = photo.String
	if !photo.Valid {
		user.Photo = ""
	}

	if birthDate.Valid {
		user.BirthDate = birthDate.Time.Format("2006-01-02")
	} else {
		user.BirthDate = ""
	}

	return &user, nil
}

func (u *UserRepository) GetUserById(ctx context.Context, req *pb.UserId) (*pb.GetUserResponse, error) {
	query := `SELECT id, name, surname, email, birth_date, gender, phone_number, address, photo, role, created_at 
	          FROM users WHERE id = $1 AND deleted_at=0`

	var (
		user      pb.GetUserResponse
		name      sql.NullString
		surname   sql.NullString
		birthDate sql.NullTime
		gender    sql.NullString
		address   sql.NullString
		photo     sql.NullString
	)

	err := u.Db.QueryRowContext(ctx, query, req.Id).Scan(
		&user.Id, &name, &surname, &user.Email,
		&birthDate, &gender, &user.PhoneNumber,
		&address, &photo, &user.Role, &user.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	// NULL bo'lishi mumkin bo'lgan maydonlarni tekshirish
	user.Name = name.String
	if !name.Valid {
		user.Name = ""
	}

	user.Surname = surname.String
	if !surname.Valid {
		user.Surname = ""
	}

	user.Gender = gender.String
	if !gender.Valid {
		user.Gender = ""
	}

	user.Address = address.String
	if !address.Valid {
		user.Address = ""
	}

	user.Photo = photo.String
	if !photo.Valid {
		user.Photo = ""
	}

	if birthDate.Valid {
		user.BirthDate = birthDate.Time.Format("2006-01-02")
	} else {
		user.BirthDate = ""
	}

	return &user, nil
}

func (u *UserRepository) UpdatePassword(ctx context.Context, req *pb.UpdatePasswordReq) error {
	query := `update users set password_hash=$1 where id=$2 and deleted_at=0`
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	result, err := u.Db.ExecContext(ctx, query, hashedPassword, req.Id)

	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

func (u *UserRepository) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) error {
	query := `UPDATE users SET `
	n := 1
	var arr []interface{}
	var updates []string

	if len(req.Name) > 0 {
		updates = append(updates, fmt.Sprintf("name=$%d", n))
		arr = append(arr, req.Name)
		n++
	}
	if len(req.Surname) > 0 {
		updates = append(updates, fmt.Sprintf("surname=$%d", n))
		arr = append(arr, req.Surname)
		n++
	}
	if len(req.BirthDate) > 0 {
		updates = append(updates, fmt.Sprintf("birth_date=TO_DATE($%d, 'DD-MM-YYYY')", n))
		arr = append(arr, req.BirthDate)
		n++
	}
	if len(req.Gender) > 0 {
		updates = append(updates, fmt.Sprintf("gender=$%d", n))
		arr = append(arr, req.Gender)
		n++
	}
	if len(req.Address) > 0 {
		updates = append(updates, fmt.Sprintf("address=$%d", n))
		arr = append(arr, req.Address)
		n++
	}
	if len(req.PhoneNumber) > 0 {
		updates = append(updates, fmt.Sprintf("phone_number=$%d", n))
		arr = append(arr, req.PhoneNumber)
		n++
	}
	if len(req.Photo) > 0 {
		updates = append(updates, fmt.Sprintf("photo=$%d", n))
		arr = append(arr, req.Photo)
		n++
	}

	// Agar hech qanday maydon yangilanmasa, hech narsa qilmang
	if len(updates) == 0 {
		return fmt.Errorf("no fields to update")
	}

	// updated_at qo'shish
	updates = append(updates, fmt.Sprintf("updated_at=CURRENT_TIMESTAMP"))

	// Yakuniy query hosil qilish
	query += strings.Join(updates, ", ")
	arr = append(arr, req.Id)
	query += fmt.Sprintf(" WHERE id=$%d AND deleted_at=0", n)

	// Queryni bajarish
	result, err := u.Db.ExecContext(ctx, query, arr...)
	if err != nil {
		return err
	}

	// O'zgargan qatorlarni tekshirish
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found or no changes made")
	}

	return nil
}

func (u *UserRepository) DeleteUser(ctx context.Context, req *pb.UserId) error {
	query := `UPDATE users SET deleted_at = date_part('epoch', current_timestamp)::INT 
	WHERE id = $1 and deleted_at=0`

	result, err := u.Db.ExecContext(ctx, query, req.Id)
	if err != nil {
		return fmt.Errorf("failed to update deleted_at: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

func (u *UserRepository) ResetPassword(ctx context.Context, req *pb.ResetPasswordReq) error {
	query := `SELECT password_hash FROM users WHERE id = $1 AND deleted_at=0`
	var passwordHash string
	err := u.Db.QueryRowContext(ctx, query, req.Id).Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("user not found")
		}
		return err
	}
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Oldpassword))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return fmt.Errorf("password is incorrect")
		}
		return err
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Newpassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	query = `UPDATE users SET password_hash=$1 WHERE id=$2 AND deleted_at=0`
	result, err := u.Db.ExecContext(ctx, query, hashedPassword, req.Id)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (u *UserRepository) IsUserExist(ctx context.Context, req *pb.UserId) error {
	var exists bool
	err := u.Db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM users
			WHERE id = $1 and deleted_at=0
		)
	`, req.GetId()).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check if user exists: %w", err)
	}

	if !exists {
		return fmt.Errorf("user with id %s does not exist", req.GetId())
	}

	return nil
}

func (u *UserRepository) DeleteMediaUser(ctx context.Context, req *pb.UserId) error {
	query := `UPDATE users SET photo = NULL 
    WHERE user_id = $1 AND deleted_at=0`

	result, err := u.Db.ExecContext(ctx, query, req.Id)
	if err != nil {
		return fmt.Errorf("failed to update photo: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user not found or user is deleted")
	}

	return nil
}
