package x

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
)

func MarshalRSAPrivate(priv *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}))
}

func MarshalRSAPublic(pub *rsa.PublicKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pub),
	}))
}

func UnmarshalPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	var err error
	key, err := x509.ParsePKCS1PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func UnmarshalPublickey(pub []byte) (*rsa.PublicKey, error) {
	var err error
	pubKey, err := x509.ParsePKCS1PublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func GenerateKey() ([]byte, []byte, error) {
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return nil, nil, err
	}

	privKey := x509.MarshalPKCS1PrivateKey(key)
	pubKey := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	return privKey, pubKey, nil
}

func Encrypt(msg string, publicKeyBytes []byte) ([]byte, error) {
	publicKey, err := UnmarshalPublickey(publicKeyBytes)
	if err != nil {
		return nil, err
	}
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, []byte(msg), nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func Decrypt(data, privKeyBytes []byte) (string, error) {
	privateKey, err := UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return "", err
	}
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, data, nil)
	if err != nil {
	}
	return string(plaintext), nil
}

func Sign(msg []byte, privKeyBytes []byte) ([]byte, error) {
	privateKey, err := UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return nil, err
	}
	hash := sha512.New()
	hash.Write(msg)
	hs := hash.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, hs)
	return signature, err
}

func Verify(msg, sig, publicKeyBytes []byte) error {
	publicKey, err := UnmarshalPublickey(publicKeyBytes)
	if err != nil {
		return err
	}
	hash := sha512.New()
	hash.Write(msg)
	hs := hash.Sum(nil)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, hs, sig)
}
