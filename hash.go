package peda

import (
	"encoding/json"
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func CreateResponse(status bool, message string, data interface{}) Response {
	response := Response{
		Status:  status,
		Message: message,
		Data:    data,
	}
	return response
}

// pengecekantoken
func IsTokenValid(publickey, tokenstr string) (payload Payload, err error) {
	var token *paseto.Token
	var pubKey paseto.V4AsymmetricPublicKey
	pubKey, err = paseto.NewV4AsymmetricPublicKeyFromHex(publickey) // this wil fail if given key in an invalid format
	if err != nil {
		fmt.Println("Decode NewV4AsymmetricPublicKeyFromHex : ", err)
	}
	parser := paseto.NewParser()                             // only used because this example token has expired, use NewParser() (which checks expiry by default)
	token, err = parser.ParseV4Public(pubKey, tokenstr, nil) // this will fail if parsing failes, cryptographic checks fail, or validation rules fail
	if err != nil {
		fmt.Println("Decode ParseV4Public : ", err)
	} else {
		json.Unmarshal(token.ClaimsJSON(), &payload)
	}
	return payload, err
}

func GenerateKey() (privatekey, publickey string) {
	secretKey := paseto.NewV4AsymmetricSecretKey() // don't share this!!!
	privatekey = secretKey.ExportHex()             // DO share this one
	publickey = secretKey.Public().ExportHex()
	return privatekey, publickey
}

func Encode(no_whatsapp, username, role, privatekey string) (string, error) {
	token := paseto.NewToken()
	token.SetIssuedAt(time.Now())
	token.SetNotBefore(time.Now())
	token.SetExpiration(time.Now().Add(2 * time.Hour))
	token.SetString("no_whatsapp", no_whatsapp)
	token.SetString("username", username)
	token.SetString("role", role)
	key, err := paseto.NewV4AsymmetricSecretKeyFromHex(privatekey)
	return token.V4Sign(key, nil), err
}

func Decode(publickey, tokenstr string) (payload Payload, err error) {
	var token *paseto.Token
	var pubKey paseto.V4AsymmetricPublicKey

	// Pastikan bahwa kunci publik dalam format heksadesimal yang benar
	pubKey, err = paseto.NewV4AsymmetricPublicKeyFromHex(publickey)
	if err != nil {
		return payload, fmt.Errorf("failed to create public key: %s", err)
	}

	parser := paseto.NewParser()

	// Pastikan bahwa token memiliki format yang benar
	token, err = parser.ParseV4Public(pubKey, tokenstr, nil)
	if err != nil {
		return payload, fmt.Errorf("failed to parse token: %s", err)
	} else {
		// Handle token claims
		json.Unmarshal(token.ClaimsJSON(), &payload)
	}

	return payload, nil
}

func DecodeGetName(publickey string, tokenstring string) string {
	payload, err := Decode(publickey, tokenstring)
	if err != nil {
		fmt.Println("Decode DecodeGetId : ", err)
	}
	return payload.No_whatsapp
}

func DecodeGetUsername(publickey string, tokenstring string) string {
	payload, err := Decode(publickey, tokenstring)
	if err != nil {
		fmt.Println("Decode DecodeGetId : ", err)
	}
	return payload.Username
}

func DecodeGetRole(publickey string, tokenstring string) string {
	payload, err := Decode(publickey, tokenstring)
	if err != nil {
		fmt.Println("Decode DecodeGetId : ", err)
	}
	return payload.Role
}
