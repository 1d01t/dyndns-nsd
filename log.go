package main

import (
	"net/http"
	"net"
	"strings"
	"database/sql"
	_ "github.com/lib/pq"
	"time"
	"os"
	"log"
)


func GetIP(r *http.Request) string {
	var ip string
	// find originating ip
	if originate := strings.Split(r.RemoteAddr, ":"); len(originate) == 2 {
		ip = originate[0]
	}
	// find forwarded-for header if exist and ise it instead
	if forwarded := strings.Trim(r.Header.Get("X-Forwarded-For"), ","); len(forwarded) > 0 {
	split := strings.Split(forwarded, ",")
	if fipsplit := net.ParseIP(split[len(split)-1]); fipsplit != nil {
		ip = fipsplit.String()
	}
	// alternate is X-Real-Ip exist use it
	} else if xforwarded := r.Header.Get("X-Real-Ip"); len(xforwarded) > 0 {
		if xip := net.ParseIP(xforwarded); xip != nil {
			ip = xip.String()
		}
	}
	return ip
}


// func to actually unban IPs
func UnbanIP(banTimes *sql.Rows) {
	for banTimes.Next() {
		var unbanIp string
		if err := banTimes.Scan(&unbanIp); err != nil {
			logging("UnbanIP - ", err.Error())
			panic(err)
		}
		logging("", ("- UnbanIP       - remove from ban table; ip: " + unbanIp))
		_, err := db.Exec("delete from ban where ip = $1;", unbanIp)
		if err != nil {
			logging("", ("UnbanIP       - " + err.Error()))
			panic(err)
		}
	}
}


func Unauthorized(ip string) {
	isPresent := AddToDb("ban", ip, 1); if isPresent.Error() == "AlreadyPresent" {
		var count int
		err := db.QueryRow("select count from ban where ip=$1", ip).Scan(&count)
		if err != nil {
			logging("Unauthorized - ", err.Error())
			panic(err)
		}
		count++
		_, err = db.Exec("update ban set count=$1 where ip=$2", count, ip)
		if err != nil {
			logging("Unauthorized - ", err.Error())
			panic(err)
		}
		if count >= Conf.BanIP.MaxTry {
			logging("", "- Unauthorized  - we'r getting bruteforced")
			_, err = db.Exec("update ban set bantime=$1 where ip=$2", time.Now().Unix() + Conf.BanIP.BanSeconds, ip)
			if err != nil {
				logging("Unauthorized - ", err.Error())
				panic(err)
			}
		} else {
			_, err = db.Exec("update ban set bantime=$1 where ip=$2", time.Now().Unix(), ip)
			if err != nil {
				logging("Unauthorized - ", err.Error())
				panic(err)
			}
		}
	}
}

// write output to log file
func logging (prefix string, logMsg string) {

	f, err := os.OpenFile(Conf.Files.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()

	logger := log.New(f, prefix, log.LstdFlags)
	logger.Println(logMsg)
}

