package peda

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
)

func Authorization(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response CredentialUser
	var auth User
	response.Status = false

	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}

	tokenusername := DecodeGetUsername(os.Getenv(publickey), header)
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)
	tokennik := DecodeGetNIK(os.Getenv(publickey), header)

	auth.Username = tokenusername

	if tokenusername == "" || tokenrole == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, auth) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	response.Message = "Berhasil decode token"
	response.Status = true
	response.Data.Username = tokenusername
	response.Data.Role = tokenrole
	response.Data.NIK = tokennik

	return GCFReturnStruct(response)
}

func Registrasi(mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}

	if UsernameExists(mongoenv, dbname, user) {
		response.Message = "Username telah dipakai"
		return GCFReturnStruct(response)
	}

	hash, hashErr := HashPassword(user.Password)
	if hashErr != nil {
		response.Message = "Gagal hash password: " + hashErr.Error()
		return GCFReturnStruct(response)
	}

	user.Password = hash

	InsertUser(mconn, collname, user)
	response.Status = true
	response.Message = "Berhasil input data"

	return GCFReturnStruct(response)
}

func Login(privatekey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, user) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !IsPasswordValid(mconn, collname, user) {
		response.Message = "Password Salah"
		return GCFReturnStruct(response)
	}

	auth := FindUser(mconn, collname, user)

	tokenstring, tokenerr := Encode(auth.Username, auth.Role, auth.NIK, os.Getenv(privatekey))
	if tokenerr != nil {
		response.Message = "Gagal encode token: " + tokenerr.Error()
		return GCFReturnStruct(response)
	}

	response.Status = true
	response.Message = "Berhasil login"
	response.Token = tokenstring

	return GCFReturnStruct(response)
}

func TambahForm(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var dataform FormInput
	err := json.NewDecoder(r.Body).Decode(&dataform)
	var buf bytes.Buffer

	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}

	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}
	tokenusername := DecodeGetUsername(os.Getenv(publickey), header)
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)

	if tokenusername == "" || tokenrole == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, User{Username: tokenusername}) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if tokenrole != "admin" && tokenrole != "dosen" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	dataform.NIK = base64.StdEncoding.EncodeToString(buf.Bytes())
	dataform.NIK, err = HashData(dataform.NIK)
	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}
	InsertForm(mconn, collname, dataform)
	response.Status = true
	response.Message = "Berhasil input data"

	return GCFReturnStruct(response)
}

func AmbilSemuaForm(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)

	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}

	tokenusername := DecodeGetUsername(os.Getenv(publickey), header)
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)

	if tokenusername == "" || tokenrole == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, User{Username: tokenusername}) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if tokenrole != "admin" && tokenrole != "dosen" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	dataform := GetAllForm(mconn, collname)
	return GCFReturnStruct(dataform)
}

func AmbilSatuFormDosen(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var dataform FormInput

	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}

	tokenusername := DecodeGetUsername(os.Getenv(publickey), header)
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)
	tokennik := DecodeGetNIK(os.Getenv(publickey), header)

	if tokenusername == "" || tokenrole == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, User{Username: tokenusername}) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if tokenrole != "admin" && tokenrole != "dosen" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	dataform.NIK = tokennik
	satuform := FindForm(mconn, collname, dataform)
	return GCFReturnStruct(satuform)
}

func AmbilSatuFormAdmin(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var dataform FormInput
	err := json.NewDecoder(r.Body).Decode(&dataform)

	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}

	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}

	tokenusername := DecodeGetUsername(os.Getenv(publickey), header)
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)

	if tokenusername == "" || tokenrole == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, User{Username: tokenusername}) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if tokenrole != "admin" && tokenrole != "dosen" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	satuform := FindForm(mconn, collname, dataform)
	return GCFReturnStruct(satuform)
}

func EditForm(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var dataform FormInput
	err := json.NewDecoder(r.Body).Decode(&dataform)

	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}

	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}
	tokenusername := DecodeGetUsername(os.Getenv(publickey), header)
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)

	if tokenusername == "" || tokenrole == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, User{Username: tokenusername}) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if tokenrole != "admin" && tokenrole != "dosen" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}
	UpdateForm(mconn, collname, dataform)
	response.Status = true
	response.Message = "Berhasil update data"

	return GCFReturnStruct(response)
}

func HapusForm(publickey, mongoenv, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	mconn := SetConnection(mongoenv, dbname)
	var dataform FormInput
	err := json.NewDecoder(r.Body).Decode(&dataform)

	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}

	header := r.Header.Get("token")
	if header == "" {
		response.Message = "Header login tidak ditemukan"
		return GCFReturnStruct(response)
	}

	tokenusername := DecodeGetUsername(os.Getenv(publickey), header)
	tokenrole := DecodeGetRole(os.Getenv(publickey), header)

	if tokenusername == "" || tokenrole == "" {
		response.Message = "Hasil decode tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if !UsernameExists(mongoenv, dbname, User{Username: tokenusername}) {
		response.Message = "Akun tidak ditemukan"
		return GCFReturnStruct(response)
	}

	if tokenrole != "admin" && tokenrole != "dosen" {
		response.Message = "Anda tidak memiliki akses"
		return GCFReturnStruct(response)
	}

	DeleteForm(mconn, collname, dataform)
	response.Status = true
	response.Message = "Berhasil hapus data"

	return GCFReturnStruct(response)
}

// Dari tim Keamanan

func Base64Encode(publickeykatalogkemanan, mongoenvkatalogfilm, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	var encryptdata FormInput
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(&encryptdata)

	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}
	encrypt := base64.StdEncoding.EncodeToString(buf.Bytes())
	response.Status = true
	response.Message = "Berhasil Encoding data"
	response.Data = encrypt

	return GCFReturnStruct(response)
}

func Encrypt(publickeykatalogkemanan, mongoenvkatalogfilm, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	var encrypting FormInput
	err := json.NewDecoder(r.Body).Decode(&encrypting)
	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}
	encrypt := Base64Encode(publickeykatalogkemanan, mongoenvkatalogfilm, dbname, collname, r)
	response.Status = true
	response.Message = "Berhasil encrypt data"
	response.Data = encrypt

	return GCFReturnStruct(response)
}

func Decrypt(publickeykatalogkemanan, mongoenvkatalogfilm, dbname, collname string, r *http.Request) string {
	var response Pesan
	response.Status = false
	var decrypting FormInput
	err := json.NewDecoder(r.Body).Decode(&decrypting)
	if err != nil {
		response.Message = "Error parsing application/json: " + err.Error()
		return GCFReturnStruct(response)
	}
	response.Status = true
	response.Message = "Berhasil decrypt data"

	return GCFReturnStruct(response)
}
