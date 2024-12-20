package trustcaptcha

import (
	"encoding/base64"
	"encoding/json"
	_ "errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

type SecretKeyInvalidError struct{}

func (e *SecretKeyInvalidError) Error() string { return "secret key invalid" }

type VerificationTokenInvalidError struct{}

func (e *VerificationTokenInvalidError) Error() string { return "verification token invalid" }

type VerificationNotFoundError struct{}

func (e *VerificationNotFoundError) Error() string { return "verification not found" }

type VerificationNotFinishedError struct{}

func (e *VerificationNotFinishedError) Error() string { return "verification not finished" }

func DecodeBase64Token(token string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, &VerificationTokenInvalidError{}
	}
	return decoded, nil
}

func ParseVerificationToken(decodedToken []byte) (*VerificationToken, error) {
	var token VerificationToken
	err := json.Unmarshal(decodedToken, &token)
	if err != nil {
		return nil, &VerificationTokenInvalidError{}
	}
	return &token, nil
}

func FetchVerificationResult(apiEndpoint, verificationId, secretKey string) (*VerificationResult, error) {
	url := apiEndpoint + "/verifications/" + verificationId + "/assessments"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("tc-authorization", secretKey)
	req.Header.Set("tc-library-language", "go")
	req.Header.Set("tc-library-version", "1.2")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusForbidden:
		return nil, &SecretKeyInvalidError{}
	case http.StatusNotFound:
		return nil, &VerificationNotFoundError{}
	case 423: // HTTP Status Code for "Locked"
		return nil, &VerificationNotFinishedError{}
	case http.StatusOK:
		// Continue processing
	default:
		return nil, fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result VerificationResult
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func GetVerificationResult(secretKey, base64VerificationToken string) (*VerificationResult, error) {
	decodedToken, err := DecodeBase64Token(base64VerificationToken)
	if err != nil {
		return nil, err
	}

	verificationToken, err := ParseVerificationToken(decodedToken)
	if err != nil {
		return nil, err
	}

	return FetchVerificationResult(verificationToken.ApiEndpoint, verificationToken.VerificationId, secretKey)
}
