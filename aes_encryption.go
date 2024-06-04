package trustcaptcha

import (
	"crypto/aes"
	"crypto/cipher"
	_ "encoding/base64"
	"errors"
)

func DecryptAccessToken(secretKey, encryptedToken []byte) (string, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	if len(encryptedToken) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := encryptedToken[:aes.BlockSize]
	encryptedToken = encryptedToken[aes.BlockSize:]

	if len(encryptedToken)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptedToken, encryptedToken)

	// Remove padding
	decrypted, err := unpad(encryptedToken, aes.BlockSize)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("input data is empty")
	}
	if len(data)%blockSize != 0 {
		return nil, errors.New("input data is not a multiple of the block size")
	}

	paddingLen := int(data[len(data)-1])
	if paddingLen > blockSize || paddingLen == 0 {
		return nil, errors.New("invalid padding length")
	}

	for _, padByte := range data[len(data)-paddingLen:] {
		if int(padByte) != paddingLen {
			return nil, errors.New("invalid padding byte")
		}
	}

	return data[:len(data)-paddingLen], nil
}
