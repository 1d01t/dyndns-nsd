package main

import (
	"net/http"
	"crypto/tls"
)

func main() {
	// read config file
	initConf()
	// initialize db connection
	initDB()
	// reduce permission rights with pledge
	PledgeAllow()
	// reduce read filesystem rights with unveil
	UnveilAllow()
	// sceduled routine to clear old entries in ban table
	go ClearDB()

	// build custom https mux server
	mux := http.NewServeMux()

	// add handler to echo ip of client
	mux.HandleFunc("/", index)

	// add handler to serve authentication and authorization
	mux.HandleFunc("/renew", renew)

	// tls settings
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
//			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
//			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	// web server settings
	srv := &http.Server{
		Addr:         ":443",
		Handler:      mux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	// HTTP
	go http.ListenAndServe(":80", http.HandlerFunc(redirect))

	// HTTPS
	err := srv.ListenAndServeTLS(Conf.HTTPS.TLScrt, Conf.HTTPS.TLSkey)
	logging("HTTPS SERVER FATAL - ", err.Error())
	panic(err)
}
