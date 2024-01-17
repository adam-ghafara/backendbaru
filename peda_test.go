package peda

import (
	"fmt"
	"testing"
)

var privatekeykatalogfilm = "0df24b8b8adab240aa59b746d904c6729f2e93eae44bb982aa2b7d64cc211878891957e37ba3bbe1f3f70e9b9b7d1e972160e513bf6af50159b3c02eb878f927"
var publickeykatalogfilm = "891957e37ba3bbe1f3f70e9b9b7d1e972160e513bf6af50159b3c02eb878f927"
var encode = ""

func TestGeneratePaseto(t *testing.T) {
	privatekeykatalogfilm, publickeykatalogfilm := GenerateKey()
	fmt.Println("Private Key: " + privatekeykatalogfilm)
	fmt.Println("Public Key: " + publickeykatalogfilm)
}

func TestEncode(t *testing.T) {
	No_whatsapp := "08123123"
	username := "RAUL"
	role := "admin"

	tokenstring, err := Encode(No_whatsapp, username, role, privatekeykatalogfilm)
	fmt.Println("error : ", err)
	fmt.Println("token : ", tokenstring)
}

func TestDecode(t *testing.T) {
	pay, err := Decode(publickeykatalogfilm, encode)
	no_whatsapp := DecodeGetName(publickeykatalogfilm, encode)
	username := DecodeGetUsername(publickeykatalogfilm, encode)
	role := DecodeGetRole(publickeykatalogfilm, encode)

	fmt.Println("no_whatsapp :", no_whatsapp)
	fmt.Println("username :", username)
	fmt.Println("role :", role)
	fmt.Println("err : ", err)
	fmt.Println("payload : ", pay)
}

func TestRegistrasi(t *testing.T) {
	mconn := SetConnection("mongoenvkatalogfilm", "sistemkeamanan")
	var user User
	user.No_whatsapp = "0881209321"
	user.Username = "Raul"
	user.Password = "Raul"
	user.Role = "admin"
	hash, hashErr := HashPassword(user.Password)
	if hashErr != nil {
		fmt.Println(hashErr)
	}
	user.Password = hash
	InsertUser(mconn, "user", user)

	fmt.Println("Berhasil insert data user")
}

func TestGetAllUser(t *testing.T) {
	mconn := SetConnection("mongoenvkatalogfilm", "sistemkeamanan")
	datauser := GetAllUser(mconn, "user")

	fmt.Println(datauser)
}

func TestFindUser(t *testing.T) {
	mconn := SetConnection("mongoenvkatalogfilm", "sistemkeamanan")
	var user User
	user.Username = "Raul"
	datauser := FindUser(mconn, "user", user)

	fmt.Println(datauser)
}

func TestIsPasswordValid(t *testing.T) {
	mconn := SetConnection("mongoenvkatalogfilm", "sistemkeamanan")
	var user User
	user.Username = "Raul"
	user.Password = "Raul"
	datauser := IsPasswordValid(mconn, "user", user)

	fmt.Println(datauser)
}

func TestUsernameExists(t *testing.T) {
	var user User
	user.Username = "Raul"
	datauser := UsernameExists("mongoenvkatalogfilm", "sistemkeamanan", user)

	fmt.Println(datauser)
}
