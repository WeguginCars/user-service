package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/spf13/cast"
)

type Config struct {
	Postgres PostgresConfig
	Server   ServerConfig
	Token    TokensConfig
	Redis    RedisConfig
	Minio    MinioConfig
	Email    EmailConfig
}

type PostgresConfig struct {
	PDB_NAME     string
	PDB_PORT     string
	PDB_PASSWORD string
	PDB_USER     string
	PDB_HOST     string
}

type RedisConfig struct {
	RDB_ADDRESS  string
	RDB_PASSWORD string
}

type ServerConfig struct {
	USER_SERVICE string
	USER_ROUTER  string
}

type TokensConfig struct {
	TOKEN_KEY string
}

type MinioConfig struct {
	MINIO_ENDPOINT          string
	MINIO_ACCESS_KEY_ID     string
	MINIO_SECRET_ACCESS_KEY string
	MINIO_BUCKET_NAME       string
	MINIO_PUBLIC_URL        string
}

type EmailConfig struct {
	SENDER_EMAIL string
	APP_PASSWORD string
}

func Load() *Config {
	if err := godotenv.Load(".env"); err != nil {
		log.Printf("error while loading .env file: %v", err)
	}

	return &Config{
		Postgres: PostgresConfig{
			PDB_HOST:     cast.ToString(coalesce("PDB_HOST", "localhost")),
			PDB_PORT:     cast.ToString(coalesce("PDB_PORT", "5432")),
			PDB_USER:     cast.ToString(coalesce("PDB_USER", "postgres")),
			PDB_NAME:     cast.ToString(coalesce("PDB_NAME", "postgres")),
			PDB_PASSWORD: cast.ToString(coalesce("PDB_PASSWORD", "3333")),
		},
		Server: ServerConfig{
			USER_SERVICE: cast.ToString(coalesce("USER_SERVICE", ":1234")),
			USER_ROUTER:  cast.ToString(coalesce("USER_ROUTER", ":1234")),
		},
		Token: TokensConfig{
			TOKEN_KEY: cast.ToString(coalesce("TOKEN_KEY", "your_secret_key")),
		},
		Redis: RedisConfig{
			RDB_ADDRESS:  cast.ToString(coalesce("RDB_ADDRESS", "localhost:6379")),
			RDB_PASSWORD: cast.ToString(coalesce("RDB_PASSWORD", "")),
		},
		Minio: MinioConfig{
			MINIO_ENDPOINT:          cast.ToString(coalesce("MINIO_ENDPOINT", "access_key")),
			MINIO_ACCESS_KEY_ID:     cast.ToString(coalesce("MINIO_ACCESS_KEY_ID", "access_key")),
			MINIO_SECRET_ACCESS_KEY: cast.ToString(coalesce("MINIO_SECRET_ACCESS_KEY", "access_key")),
			MINIO_BUCKET_NAME:       cast.ToString(coalesce("MINIO_BUCKET_NAME", "twit_images")),
			MINIO_PUBLIC_URL:        cast.ToString(coalesce("MINIO_PUBLIC_URL", "http://localhost:9000/minio/")),
		},
		Email: EmailConfig{
			SENDER_EMAIL: cast.ToString(coalesce("SENDER_EMAIL", "your_email@example.com")),
			APP_PASSWORD: cast.ToString(coalesce("APP_PASSWORD", "your_password")),
		},
	}
}

func coalesce(key string, value interface{}) interface{} {
	val, exist := os.LookupEnv(key)
	if exist {
		return val
	}
	return value
}
