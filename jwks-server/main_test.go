package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWKSHandler(t *testing.T) {
	server := NewServer()

	req, err := http.NewRequest("GET", "/.well-known/jwks.json", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.JWKSHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("JWKSHandler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response JWKS
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse JWKS JSON response: %v", err)
	}

	// Verify that only the 1 unexpired key is returned
	if len(response.Keys) != 1 {
		t.Errorf("Expected 1 valid key in JWKS, got %d", len(response.Keys))
	}

	if response.Keys[0].Kid != "active-key-1" {
		t.Errorf("Expected key ID 'active-key-1', got '%s'", response.Keys[0].Kid)
	}
}

func TestAuthHandlerValidKey(t *testing.T) {
	server := NewServer()

	req, err := http.NewRequest("POST", "/auth", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.AuthHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("AuthHandler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse Auth response: %v", err)
	}

	tokenStr, exists := response["token"]
	if !exists || tokenStr == "" {
		t.Fatal("Response did not contain a valid token")
	}

	// Parse token header without verifying signature to check 'kid' header
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("Failed to parse issued JWT: %v", err)
	}

	if kid, ok := token.Header["kid"].(string); !ok || kid != "active-key-1" {
		t.Errorf("Expected JWT 'kid' header to be 'active-key-1', got '%v'", token.Header["kid"])
	}
}

func TestAuthHandlerExpiredKey(t *testing.T) {
	server := NewServer()

	req, err := http.NewRequest("POST", "/auth?expired=true", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.AuthHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("AuthHandler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var response map[string]string
	json.Unmarshal(rr.Body.Bytes(), &response)
	tokenStr := response["token"]

	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("Failed to parse issued JWT: %v", err)
	}

	if kid, ok := token.Header["kid"].(string); !ok || kid != "expired-key-1" {
		t.Errorf("Expected JWT 'kid' header to be 'expired-key-1', got '%v'", token.Header["kid"])
	}
}

func TestMethodNotAllowed(t *testing.T) {
	server := NewServer()

	req, _ := http.NewRequest("GET", "/auth", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(server.AuthHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("Expected HTTP 405 Method Not Allowed, got %v", status)
	}
}
