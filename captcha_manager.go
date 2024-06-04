package trustcaptcha

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
)

func DecodeBase64Token(token string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func ParseVerificationToken(decodedToken []byte) (*VerificationToken, error) {
	var token VerificationToken
	err := json.Unmarshal(decodedToken, &token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func FetchVerificationResult(apiEndpoint, verificationId, accessToken string) (*VerificationResult, error) {
	url := apiEndpoint + "/verifications/" + verificationId + "/assessments?accessToken=" + accessToken
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("verification not found")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve verification result")
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

func GetVerificationResult(base64SecretKey, base64VerificationToken string) (*VerificationResult, error) {
	decodedToken, err := DecodeBase64Token(base64VerificationToken)
	if err != nil {
		return nil, err
	}

	verificationToken, err := ParseVerificationToken(decodedToken)
	if err != nil {
		return nil, err
	}

	secretKey, err := DecodeBase64Token(base64SecretKey)
	if err != nil {
		return nil, err
	}

	encryptedAccessToken, err := DecodeBase64Token(verificationToken.EncryptedAccessToken)
	if err != nil {
		return nil, err
	}

	decryptedAccessToken, err := DecryptAccessToken(secretKey, encryptedAccessToken)
	if err != nil {
		return nil, err
	}

	return FetchVerificationResult(verificationToken.ApiEndpoint, verificationToken.VerificationId, decryptedAccessToken)
}
