package redis

import (
	"context"
	"fmt"
	"time"
	"wegugin/config"

	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
)

func ConnectDB() *redis.Client {
	conf := config.Load()
	rdb := redis.NewClient(&redis.Options{
		Addr:     conf.Redis.RDB_ADDRESS,
		Password: conf.Redis.RDB_PASSWORD,
		DB:       0,
	})

	return rdb
}
func StoreCodes(ctx context.Context, code, email string) error {
	rdb := ConnectDB()

	err := rdb.Set(ctx, email, code, 10*time.Minute).Err()
	if err != nil {
		return errors.Wrap(err, "failed to set code in Redis")
	}

	return nil
}

func GetCodes(ctx context.Context, email string) (string, error) {
	rdb := ConnectDB()
	code, err := rdb.Get(ctx, email).Result()
	if err != nil {
		if err == redis.Nil {
			return "", fmt.Errorf("no code found for email: %s", email)
		}
		return "", errors.Wrap(err, "failed to get code from Redis")
	}
	return code, nil
}
