package main

import (
	"time"
	"database/sql"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"errors"
)

// func to scadualy check if banned IPs can get unbanned
func ClearDB() {
	for true {
		time.Sleep(time.Duration(Conf.BanIP.UnbanCheck * 1000) * time.Millisecond)
		logging("", "- ClearDB       - I am a scedueled go routine to delete old entries in the ban table")
		banTimes, err := db.Query("SELECT ip FROM ban WHERE count >= $1 AND bantime < $2;", Conf.BanIP.MaxTry, time.Now().Unix())
		if err != nil {
			logging("", "ClearDB       - " + err.Error())
			panic(err)
		}
		UnbanIP(banTimes)
		banTimes, err = db.Query("SELECT ip FROM ban WHERE count < $1 AND bantime < $2;", Conf.BanIP.MaxTry, time.Now().Unix() - Conf.BanIP.LogTime)
		if err != nil {
			logging("", "ClearDB       - " + err.Error())
			panic(err)
		}
		UnbanIP(banTimes)
	}
}

// add ip to ban table if not exist
func AddToDb(table string, name string, var1 int) (error) {
	var exists string
	var err error
	// check for existence
	err = db.QueryRow("select ip from ban where ip=$1", name).Scan(&exists)
	if err != nil && err != sql.ErrNoRows {
		logging("", ("- AddToDb       - Error while reading from db " + err.Error()))
		return err
	}
	if len(exists) != 0 {
		// there is already an entry present
		logging("", "- AddToDb       - there is already an entry in db")
		return errors.New("AlreadyPresent")
	}
	// username does not exist. Continue
	logging("", "- AddToDb       - Does not exist in DB. Adding it")
	_, err = db.Exec("insert into ban values ($1, $2, $3)", name, var1, time.Now().Unix())
	if err != nil {
		// error while writing to db
		logging("AddToDb - ", err.Error())
		panic(err)
	}
	return errors.New("EntryAdded")
}

// update ip in hosts table if needed
func UpdateIp (updateDomainname string, updateIp string) (bool) {
	var oldIP string
	err := db.QueryRow("select ip from hosts where domainname=$1", updateDomainname).Scan(&oldIP)
	if err != nil {
		logging("", ("- UpdateIp      - Domainname " + updateDomainname + " not found in db: " + err.Error()))
		panic(err)
	}
	if oldIP == updateIp {
		logging("", ("- UpdateIp      - IP is still the same: " + oldIP))
		return false
	} else {
		_, err = db.Exec("update hosts set ip=$1, time=$2 where domainname=$3;", updateIp, time.Now(), updateDomainname)
		if err != nil {
			logging("", ("- UpdateIp      - Error while updating ip in db:" + err.Error()))
			panic(err)
		}
	}
	return true
}

// get from ban table if ip is listed
func IpInBanDb(ip string) (bool) {
	var deny string
	err := db.QueryRow("select ip from ban where ip=$1 and count >= $2", ip, Conf.BanIP.MaxTry).Scan(&deny)
	if err != nil && err != sql.ErrNoRows {
		panic(err)
	}
	if len(deny) != 0 {
		logging("", ("- Handler renew - DENY ACCES TO DYNDNS BECAUSE OF BRUTEFORCE FOR: " + deny))
		return true
	}
	return false
}

// get from users table if hashed password of requested user is correct
func credsCheck(requestAuth *Authentication, ip string) (bool) {
	var dbPasswd string
	err := db.QueryRow("select password from users where username=$1", requestAuth.username).Scan(&dbPasswd)
	if err != nil {
		if err == sql.ErrNoRows {
			// username does not exist
			logging("", "- credsCheck    - Username " + requestAuth.username + " does not exist")
			Unauthorized(ip)
			return false
		} else {
			// error with connecting the db
			logging("", "- credsCheck    - Error while reading pwd from db")
			panic(err)
		}
	}
	err = bcrypt.CompareHashAndPassword([]byte(dbPasswd), []byte(requestAuth.password))
	if err != nil {
		logging("", "- credsCheck    - Wrong Password")
		Unauthorized(ip)
		return false
	}
	return true
}

// get from hosts table if user is authorized for requested domain
func authorizeCheck(requestUsername string, requestDomainname string) (bool) {
	var authorizedUsername string
	err := db.QueryRow("select username from hosts where domainname=$1", requestDomainname).Scan(&authorizedUsername)
	if err != nil {
		// Domainname was not found in db
		logging("", ("- authorizeCheck- Domainname " + requestDomainname + " not found in db: " + err.Error()))
		return false
	}
	if authorizedUsername == requestUsername {
		return true
	} else {
		logging("", ("- authorizeCheck- Domainname " + requestUsername + " is not authorized for " + requestDomainname))
		return false
	}
}
