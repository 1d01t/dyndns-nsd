package main

import (
	"io/ioutil"
	"strings"
	"regexp"
	"strconv"
	"encoding/hex"
	"crypto/rand"
	"crypto/sha256"
	"os/exec"
	"bytes"
)

// function to change domainname ip in zonefile
func changeIpInZone(search string, replace string) {
	DomainnameExist := false
        // read zonefile

	zoneFile, err := ioutil.ReadFile(Conf.Files.ZoneFile)
	if err != nil {
		// error while reading zonefile
		logging("", ("changeIpInZone - failed reading data from file: " + err.Error()))
		panic(err)
	}

	// split file in lines
	lines := strings.Split(string(zoneFile), "\n")

	if lines[len(lines)-1] == "" {
		// remove last empty line of zonefile
		lines = lines[:len(lines)-1]
	}

	for i, line := range lines {
		if strings.Contains(line, "; serial number") {
			// regex to filter only old serial
			re := regexp.MustCompile("[0-9]+")
			// extract serial of zonefile
			serial, err := strconv.Atoi(re.FindAllString(lines[i], -1)[0])
			if err != nil {
				// error by extracting old serial
				logging("", ("changeIpInZone - failed to extract old serial: " + err.Error()))
				panic(err)
			}
			/// increment old serial and replace it
			lines[i] = "	" + strconv.Itoa(serial + 1) + "     ; serial number"
		}
		if strings.Contains(line, search) {
			lines[i] = replace
			DomainnameExist = true
		}
	}
	if DomainnameExist == false {
		// domainname does not exist in zonefile
		logging("", "changeIpInZone - No domainname entry found in file, adding it")
		lines = append(lines, replace)
	}
	// merge line to file again
	newZonefile := strings.Join(lines, "\n")
	// write new zonefile
	err = ioutil.WriteFile(Conf.Files.ZoneFile, []byte(newZonefile), 0644)
	if err != nil {
		// error while writing new zonefile
		logging("", ("changeIpInZone - failed to write to new zone file " + err.Error()))
		panic(err)
	}

	// Sign new Zonefile
	SignZone()
}


// execute cmd commands
func executeCMD(cmd *exec.Cmd) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		panic(err)
	}
	cmd.Wait()
	if len(stderr.String()) != 0 {
		logging("", "executeCMD     - STDERR: "+strings.TrimSuffix(stderr.String(), "\n"))
	}
	if len(stdout.String()) != 0 {
		logging("", "executeCMD     - STDOUT: "+strings.TrimSuffix(stdout.String(), "\n"))
	}
}


func SignZone() {

	// generate random 32 chars long salt
	randslice := make([]byte, 64)
	if _, err := rand.Read(randslice); err != nil {
		panic(err)
	}
	sha := sha256.Sum256(randslice)
	salt := hex.EncodeToString(sha[:])[0:32]

	// sign zone
	executeCMD(exec.Command(Conf.Singning.ZoneSigner, "-n", "-p", "-s", salt, Conf.Files.ZoneFile, Conf.Singning.ZSK, Conf.Singning.KSK))
	executeCMD(exec.Command("/usr/sbin/nsd-control", "reload"))
	executeCMD(exec.Command("/usr/sbin/nsd-control", "notify"))
	logging("", "SignZone       - Signed new zone file")
}
