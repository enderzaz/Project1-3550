package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type KeyPair struct {
	ID         string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Expiry     time.Time
}

type Server struct {
	mu   sync.RWMutex
	keys map[string]KeyPair
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func NewServer() *Server {
	s := &Server{
		keys: make(map[string]KeyPair),
	}
	s.generateKey("active-key-1", time.Now().Add(24*time.Hour))
	s.generateKey("expired-key-1", time.Now().Add(-1*time.Hour))
	return s
}

func (s *Server) generateKey(kid string, expiry time.Time) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[kid] = KeyPair{
		ID:         kid,
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		Expiry:     expiry,
	}
}

func (s *Server) JWKSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var validKeys []JWK
	now := time.Now()

	for _, kp := range s.keys {
		if kp.Expiry.After(now) {
			nStr := base64.RawURLEncoding.EncodeToString(kp.PublicKey.N.Bytes())
			eStr := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(kp.PublicKey.E)).Bytes())

			validKeys = append(validKeys, JWK{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: kp.ID,
				N:   nStr,
				E:   eStr,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JWKS{Keys: validKeys})
}

func (s *Server) AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	useExpired := r.URL.Query().Get("expired") == "true"

	s.mu.RLock()
	var selectedKey KeyPair
	found := false
	now := time.Now()

	for _, kp := range s.keys {
		if useExpired && kp.Expiry.Before(now) {
			selectedKey = kp
			found = true
			break
		} else if !useExpired && kp.Expiry.After(now) {
			selectedKey = kp
			found = true
			break
		}
	}
	s.mu.RUnlock()

	if !found {
		http.Error(w, "No suitable key found to sign token", http.StatusInternalServerError)
		return
	}

	tokenExpiry := time.Now().Add(1 * time.Hour)
	if useExpired {
		tokenExpiry = time.Now().Add(-1 * time.Hour)
	}

	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "jwks-auth-server",
		"exp": tokenExpiry.Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = selectedKey.ID

	signedString, err := token.SignedString(selectedKey.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": signedString,
	})
}

func main() {
	server := NewServer()

	http.HandleFunc("/.well-known/jwks.json", server.JWKSHandler)
	http.HandleFunc("/auth", server.AuthHandler)

	port := "8080"
	fmt.Printf("JWKS Server listening on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
