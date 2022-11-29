package limiter

import (
	"github.com/go-redis/redis/v8"
)

type GlobalDeviceLimitConfig struct {
	Enable        bool   `mapstructure:"Enable"`
	RedisAddr     string `mapstructure:"RedisAddr"` // host:port
	RedisPassword string `mapstructure:"RedisPassword"`
	RedisDB       int    `mapstructure:"RedisDB"`
	Timeout       int    `mapstructure:"Timeout"`
	Expiry        int    `mapstructure:"Expiry"` // second
	R             *redis.Client
}
