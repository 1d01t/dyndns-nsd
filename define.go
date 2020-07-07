package main

import (
	"database/sql"
	_ "github.com/lib/pq"
)

//Structs section
type Config struct {
	HTTPS struct {
		TLScrt string `yaml:"tls-crt"`
		TLSkey string `yaml:"tls-key"`
	} `yaml:"HTTPS"`
	DB struct {
		Host string `yaml:"host"`
		Port int `yaml:"port"`
		User string `yaml:"user"`
		Pass string `yaml:"pass"`
		DBname string `yaml:"dbname"`
	} `yaml:"Database"`
	BanIP struct {
		UnbanCheck int64 `yaml:"unbanCheck"`
		BanSeconds int64 `yaml:"banSeconds"`
		MaxTry int `yaml:"maxTry"`
		LogTime int64 `yaml:"logTime"`
	} `yaml:"BanIP"`
	Files struct {
		LogFile string `yaml:"logfile"`
		ZoneFile string `yaml:"zonefile"`
	} `yaml:"Files"`
	Singning struct {
		ZoneSigner string `yaml:"zonesigner"`
		KSK string `yaml:"ksk"`
		ZSK string `yaml:"zsk"`
	} `yaml:"Singning"`
}

type Authentication struct {
        username string
	password string
}

type Authorization struct {
        domainname string
        username string
        ip string
}




// Global vars
var Conf Config		// configs from yaml file
var db *sql.DB		// postgres DB

