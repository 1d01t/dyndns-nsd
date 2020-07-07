package main

import (
	"golang.org/x/sys/unix"
)

func PledgeAllow() {
	// for security use pledge
	err := unix.Pledge("stdio error inet unveil rpath wpath cpath proc exec","stdio unix error rpath wpath cpath")
//	err := unix.Pledge("stdio error rpath wpath cpath","")
	if err != nil {
		panic(err)
	}
}

// permit or deny file system acces
func Unveil (path string, flags string) {
	err := unix.Unveil(path, flags)
	if err != nil {
		panic("path= " + path + "  ---  error= " + err.Error())
	}
}

func UnveilAllow() {
	// permission for postgres
	Unveil("/var/postgresql/", "rw")
	Unveil("/etc/hosts", "r")

	// permission for ssl certicicates
	Unveil(Conf.HTTPS.TLScrt, "r")
	Unveil(Conf.HTTPS.TLSkey, "r")

	// permission for log file
	Unveil(Conf.Files.LogFile, "wc") 

	// permission for signing ZoneFile
	Unveil(Conf.Singning.ZoneSigner, "x")
	Unveil(Conf.Files.ZoneFile, "rwc")
	Unveil(Conf.Files.ZoneFile+".signed", "wc")
	Unveil(Conf.Singning.ZSK+".key", "r")
	Unveil(Conf.Singning.ZSK+".private", "r")
	Unveil(Conf.Singning.KSK+".key", "r")
	Unveil(Conf.Singning.KSK+".private", "r")
	Unveil("/usr/sbin/nsd-control", "x")
	Unveil("/var/nsd/etc/nsd.conf", "r")
	Unveil("/var/run/nsd.sock", "r")
	Unveil("/var/run/ld.so.hints", "r")
	Unveil("/usr/lib/", "r")
	Unveil("/usr/local/", "r")
	Unveil("/usr/libexec/", "r")

//	// lock down unveil
//	Unveil("", "")
}
