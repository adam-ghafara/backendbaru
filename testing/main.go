package main

import (
	"fmt"
	"log"
	"net/http"

	peda "github.com/SISTEMKEAMANAN3C/backendbaru"
)

func AuthorizationAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,Token")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	fmt.Fprintf(w, peda.Authorization("publickey", "mongoenv", "sistemkeamanan", "user", r))
}

func RegistrasiAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,Token")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	fmt.Fprintf(w, peda.Registrasi("mongoenv", "sistemkeamanan", "user", r))
}

func LoginAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,Token")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	fmt.Fprintf(w, peda.Login("privatekey", "mongoenv", "sistemkeamanan", "user", r))
}
func TambahFilmAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,Token")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	fmt.Fprintf(w, peda.TambahForm("publickey", "mongoenv", "sistemkeamanan", "form", r))
}
func DeleteAllform(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,Token")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	fmt.Fprintf(w, peda.HapusForm("publickey", "mongoenv", "sistemkeamanan", "form", r))
}

func UpdateAllform(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,Token")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	fmt.Fprintf(w, peda.EditForm("publickey", "mongoenv", "sistemkeamanan", "form", r))
}

func GetAllform(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,Token")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	fmt.Fprintf(w, peda.AmbilSemuaForm("publickey", "mongoenv", "sistemkeamanan", "form", r))
}

func handlerRequests() {
	http.HandleFunc("/AuthorizationAPI", AuthorizationAPI)
	http.HandleFunc("/RegistrasiAPI", RegistrasiAPI)
	http.HandleFunc("/LoginAPI", LoginAPI)

	http.HandleFunc("/TambahFilmAPI", TambahFilmAPI)
	http.HandleFunc("/DeleteAllform", DeleteAllform)
	http.HandleFunc("/UpdateAllform", UpdateAllform)
	// http.HandleFunc("/GetAllformOne", GetAllformOne)
	http.HandleFunc("/GetAllform", GetAllform)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func main() {
	handlerRequests()
}
