package main

import (
	"net/http"
	"net"
)

// redirect http traffic to https
func redirect(w http.ResponseWriter, r *http.Request) {
	ip := GetIP(r)

	// check if already banned from server
	if isBanned := IpInBanDb(ip); isBanned == true || len(ip) == 0 {
		http.Error(w, "you are banned", http.StatusForbidden)
		return
	}

	// add https in front of url path
	target := "https://" + r.Host + r.URL.Path
	// add query parameter
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}
	logging("", "- redirect      - redirected request from: " + ip + " to: " + target)
	http.Redirect(w, r, target, http.StatusMovedPermanently)
	w.Write([]byte(ip))
}

// function to return ip to requester
func index(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	ip := GetIP(r)

	// check if already banned from server
	if isBanned := IpInBanDb(ip); isBanned == true || len(ip) == 0 {
		http.Error(w, "you are banned", http.StatusForbidden)
		return
	}
	if r.URL.Path != "/" {
		logging("", ("- index main    - "+ip+" requested non existing handler: " + r.URL.String()))
		http.NotFound(w, r)
		return
	}
	w.Write([]byte("<html><head><title>Current IP Check</title></head><body>Current IP Address: "+ip+"</body></html>"))
}

// function to get data from request
func renew(w http.ResponseWriter, r *http.Request) {
	// allow only https
	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

	ip := GetIP(r)
	// check if already banned from server
	if isBanned := IpInBanDb(ip); isBanned == true || len(ip) == 0 {
		http.Error(w, "you are banned", http.StatusForbidden)
		return
	}

	// receive data
	ip, requestAuth, requestUpdate := GetRequest(r)

	// error handling
	if len(ip) == 0 {
		logging("", "- Handler renew - could not find an ip. return")
		http.Error(w, "no ip found", http.StatusBadRequest)
		return
	}
	if requestAuth == nil {
		Unauthorized(ip)
		logging("", "- Handler renew - Error in http header. No creds recieved")
		http.Error(w, "no creds recieved", http.StatusForbidden)
		return
	}
	if requestUpdate == nil {
		logging("", "- Handler renew - Parameter domainname is missing")
		http.Error(w, "no domain to update recieved", http.StatusBadRequest)
		return
	}

	// check validation of given data
	status, message :=ValidateRequest(ip, requestAuth, requestUpdate)
	if status == false {
		http.Error(w, message, http.StatusForbidden)
		return
	} else {
		http.Error(w, message, http.StatusAccepted)
		return
	}
}

// Get data from client
func GetRequest(r *http.Request) (string, *Authentication, *Authorization) {
	var ip string
	requestAuth := &Authentication{}
	requestUpdate := &Authorization{}

	// get client IP
	ip = GetIP(r)

	// get send header with basic auth creds
	var OK bool
	requestAuth.username, requestAuth.password, OK = r.BasicAuth()
        if OK == false {
		// error in basic auth header. No creds recieved
		return ip, nil, nil
		}

	// get send content
	requestUpdate.domainname = r.URL.Query().Get("domainname")
	if len(requestUpdate.domainname) == 0 {
		// parameter domainname is missing
		return ip, requestAuth, nil
	}
	requestUpdate.ip = r.URL.Query().Get("newip")

	// test if string is given and if string is in ip format
	if len(net.ParseIP(requestUpdate.ip)) == 0 {
		// no ip send. Try to get it from header
		requestUpdate.ip = GetIP(r)
		if len(requestUpdate.ip) == 0 {
			// could not find any ip
			return "", nil, nil
		}
	}
	return ip, requestAuth, requestUpdate
}

// Validate given data
func ValidateRequest(ip string, requestAuth *Authentication, requestUpdate *Authorization) (bool, string){
	// check if requested ip is banned
	if isBanned := IpInBanDb(ip); isBanned == true {
		return false, "you are banned"
	}

	// check if username and password are valid
	if isValid := credsCheck(requestAuth, ip); isValid == false {
		return false, "wrong creds"
	}

	// check if username is authorized for domainname
	if isAuthorized := authorizeCheck(requestAuth.username, requestUpdate.domainname); isAuthorized == false {
		return false, "user not authorized for domainname"
	}

	// check if ip needs renewal; if so write to hosts table
	if isUpdated := UpdateIp(requestUpdate.domainname, requestUpdate.ip); isUpdated == true {
		// update ip in Zonefile
		changeIpInZone(requestUpdate.domainname, (requestUpdate.domainname + ".                     IN      A       " + requestUpdate.ip))
		logging("", ("changeIpInZone - Sucesfully updated Domain: " + requestUpdate.domainname + " with new IP: " + requestUpdate.ip))
		return true, "updated ip"
	} else {
		return true, "no update needed"
	}

}
