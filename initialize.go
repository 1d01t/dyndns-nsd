package main

import (
	"database/sql"
	_ "github.com/lib/pq"
	"strconv"
	"os"
	"fmt"
	"gopkg.in/yaml.v3"
)

func initDB(){
	var err error
	// Connect to the postgres db
	db, err = sql.Open("postgres", "host="+Conf.DB.Host+" port="+strconv.Itoa(Conf.DB.Port)+" user="+Conf.DB.User+" password="+Conf.DB.Pass+" dbname="+Conf.DB.DBname+" sslmode=disable")
	if err != nil {
		// error while conecting db
		panic(err)
	}
}

func initConf() {
	var cfg string
	switch len(os.Args[1:]) {
		case 0:
			cfg = "/etc/dyndns.yml"
		case 1:
			cfg = os.Args[1]
		default:
			fmt.Println("usage: dyndns <optional configFile path>")
			os.Exit(0)
	}

	file, err := os.Open(cfg)
	if err != nil {
		logging("", err.Error())
		panic(err)
	}
	defer file.Close()

	decode := yaml.NewDecoder(file)
	err = decode.Decode(&Conf)
	if err != nil {
		logging("", err.Error())
		panic(err)
	}
}
