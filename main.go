package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"
)

type Config struct {
	ZitadelTokenURL    string
	ClientID           string
	ClientSecret       string
	ZitadelUserInfoURL string
	RedisAddr          string
	RedisPassword      string
	RedisDB            int
	GoEnv              string
}

const (
// zitadelTokenURL    = os.Getenv("ZITADEL_TOKEN_URL")
// clientID           = os.Getenv("CLIENT_ID")
// clientSecret       = os.Getenv("CLIENT_SECRET")
// zitadelUserInfoURL = os.Getenv("ZITADEL_USERINFO_URL")
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
}

type UserInfo struct {
	Sub      string `json:"sub"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Picture  string `json:"picture,omitempty"`
	Verified bool   `json:"email_verified"`
}

// Tambahkan distributed cache seperti Redis
type TokenCache struct {
	redis *redis.Client
}

func LoadConfig() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		return nil, fmt.Errorf("error loading .env file: %w", err)
	}

	redisDB := 0 // default value
	if dbStr := os.Getenv("REDIS_DB"); dbStr != "" {
		db, err := strconv.Atoi(dbStr)
		if err != nil {
			return nil, fmt.Errorf("invalid REDIS_DB value: %w", err)
		}
		redisDB = db
	}

	return &Config{
		ZitadelTokenURL:    os.Getenv("ZITADEL_TOKEN_URL"),
		ClientID:           os.Getenv("CLIENT_ID"),
		ClientSecret:       os.Getenv("CLIENT_SECRET"),
		ZitadelUserInfoURL: os.Getenv("ZITADEL_USERINFO_URL"),
		RedisAddr:          os.Getenv("REDIS_ADDR"),
		RedisPassword:      os.Getenv("REDIS_PASSWORD"),
		RedisDB:            redisDB,
		GoEnv:              os.Getenv("GO_ENV"),
	}, nil
}

func NewTokenCache(config *Config) *TokenCache {
	rdb := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
		OnConnect: func(ctx context.Context, cn *redis.Conn) error {
			log.Printf("Attempting to connect to Redis at %s", config.RedisAddr)
			return nil
		},
	})

	// Test the connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Printf("Failed to connect to Redis at %s: %v", config.RedisAddr, err)
		// Don't fatal here, let the application continue
	} else {
		log.Printf("Successfully connected to Redis at %s", config.RedisAddr)
	}

	return &TokenCache{
		redis: rdb,
	}
}

// SaveToken saves token to Redis
func (tc *TokenCache) SaveToken(token *TokenResponse) error {
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	ctx := context.Background()
	err = tc.redis.Set(ctx, "access_token", tokenBytes, time.Duration(token.ExpiresIn)*time.Second).Err()
	if err != nil {
		return fmt.Errorf("failed to save token to redis: %w", err)
	}

	return nil
}

// GetToken retrieves token from Redis
func (tc *TokenCache) GetToken() (*TokenResponse, error) {
	ctx := context.Background()
	tokenBytes, err := tc.redis.Get(ctx, "access_token").Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Token not found
		}
		return nil, fmt.Errorf("failed to get token from redis: %w", err)
	}

	var token TokenResponse
	if err := json.Unmarshal(tokenBytes, &token); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	return &token, nil
}

var tokenCache = NewTokenCache(&Config{})

func getTokenWithBasicAuth(config *Config) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	// Add role scope specifically
	scopes := []string{
		"openid",
		"profile",
		"email",
		"urn:zitadel:iam:org:project:roles",
		"urn:iam:org:project:roles",
		"urn:zitadel:iam:org:project:id:zitadel:aud",
	}

	data.Set("scope", strings.Join(scopes, " "))

	req, err := http.NewRequest("POST", config.ZitadelTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(config.ClientID, config.ClientSecret)

	// Do the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status: %s", resp.Status)
	}

	var tokenResp TokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &tokenResp, nil
}

func getUserInfo(accessToken string, config *Config) (*UserInfo, error) {
	req, err := http.NewRequest("GET", config.ZitadelUserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status: %s", resp.Status)
	}

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &userInfo, nil
}

// Update tokenMiddleware to accept config
func tokenMiddleware(config *Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			currentToken, err := tokenCache.GetToken()
			if err != nil || currentToken == nil {
				// Get new token internally with proper config
				newToken, err := getTokenWithBasicAuth(config)
				if err != nil {
					return c.JSON(http.StatusInternalServerError, map[string]string{
						"error": fmt.Sprintf("error getting token: %v", err),
					})
				}

				if err := tokenCache.SaveToken(newToken); err != nil {
					log.Printf("Error saving token: %v", err)
				}

				c.Set("access_token", newToken.AccessToken)
				return next(c)
			}

			c.Set("access_token", currentToken.AccessToken)
			return next(c)
		}
	}
}

func securityMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Add security headers
		c.Response().Header().Set("X-Content-Type-Options", "nosniff")
		c.Response().Header().Set("X-Frame-Options", "DENY")
		c.Response().Header().Set("X-XSS-Protection", "1; mode=block")

		// Force HTTPS in production
		if c.Scheme() != "https" && os.Getenv("GO_ENV") == "production" {
			return c.Redirect(http.StatusPermanentRedirect,
				"https://"+c.Request().Host+c.Request().URL.String())
		}

		return next(c)
	}
}

var limiter = rate.NewLimiter(rate.Every(time.Second), 10) // 10 requests per second

func rateLimitMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if !limiter.Allow() {
			return c.JSON(http.StatusTooManyRequests, map[string]string{
				"error": "rate limit exceeded",
			})
		}
		return next(c)
	}
}

func main() {
	// Load configuration
	config, err := LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize Echo
	e := echo.New()

	// Initialize TokenCache with config
	tokenCache = NewTokenCache(config)

	// Apply middleware globally
	e.Use(tokenMiddleware(config))
	e.Use(securityMiddleware)
	e.Use(rateLimitMiddleware)

	e.GET("/userinfo", func(c echo.Context) error {
		// Get token from context (set by middleware)
		accessToken := c.Get("access_token").(string)
		if accessToken == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "unauthorized",
			})
		}

		// Use the cached token to get user info
		userInfo, err := getUserInfo(accessToken, config)
		if err != nil {
			log.Printf("Error getting user info: %v", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		return c.JSON(http.StatusOK, userInfo)
	})

	e.Logger.Fatal(e.Start(":8080"))
}
