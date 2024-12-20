package trustcaptcha

import (
	"errors"
	"testing"
)

const validToken = "eyJhcGlFbmRwb2ludCI6Imh0dHBzOi8vYXBpLmNhcHRjaGEudHJ1c3RjYXB0Y2hhLmNvbSIsInZlcmlmaWNhdGlvbklkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIn0="
const notFoundToken = "eyJhcGlFbmRwb2ludCI6Imh0dHBzOi8vYXBpLmNhcHRjaGEudHJ1c3RjYXB0Y2hhLmNvbSIsInZlcmlmaWNhdGlvbklkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAxIn0="
const lockedToken = "eyJhcGlFbmRwb2ludCI6Imh0dHBzOi8vYXBpLmNhcHRjaGEudHJ1c3RjYXB0Y2hhLmNvbSIsInZlcmlmaWNhdGlvbklkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAyIn0="
const invalidToken = "invalid-base64"

func TestSuccessfulVerification(t *testing.T) {
	result, err := GetVerificationResult("secret-key", validToken)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if result.VerificationId != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("Unexpected verification ID: %v", result.VerificationId)
	}
}

func TestVerificationTokenInvalid(t *testing.T) {
	_, err := GetVerificationResult("secret-key", invalidToken)
	if err == nil {
		t.Fatal("Expected error but got nil")
	}
	var tokenErr *VerificationTokenInvalidError
	if !errors.As(err, &tokenErr) {
		t.Fatalf("Expected VerificationTokenInvalidError, got: %v", err)
	}
}

func TestVerificationNotFound(t *testing.T) {
	_, err := GetVerificationResult("secret-key", notFoundToken)
	if err == nil {
		t.Fatal("Expected error but got nil")
	}
	var notFoundErr *VerificationNotFoundError
	if !errors.As(err, &notFoundErr) {
		t.Fatalf("Expected VerificationNotFoundError, got: %v", err)
	}
}

func TestSecretKeyInvalid(t *testing.T) {
	_, err := GetVerificationResult("invalid-key", validToken)
	if err == nil {
		t.Fatal("Expected error but got nil")
	}
	var keyErr *SecretKeyInvalidError
	if !errors.As(err, &keyErr) {
		t.Fatalf("Expected SecretKeyInvalidError, got: %v", err)
	}
}

func TestVerificationNotFinished(t *testing.T) {
	_, err := GetVerificationResult("secret-key", lockedToken)
	if err == nil {
		t.Fatal("Expected error but got nil")
	}
	var lockedErr *VerificationNotFinishedError
	if !errors.As(err, &lockedErr) {
		t.Fatalf("Expected VerificationNotFinishedError, got: %v", err)
	}
}
