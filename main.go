package main

import (
	"net"
	"os"
)

func main() {
	badIPChannel := make(chan net.IP, 10)
	errChannel := make(chan error)
	journal := NewJournal(badIPChannel, errChannel, 3)
	iptablesBlocker, err := NewIPtablesBlocker(badIPChannel, errChannel)
	if err != nil {
		fatalLogger.Println(err)
		os.Exit(1)
	}

	go journal.Run()
	go iptablesBlocker.startBlockingIPs()

	infoLogger.Println("brutedef running...")
	// read errors from errChannel and exit when an err is received
	err = <-errChannel
	if err != nil {
		fatalLogger.Println(err)
		os.Exit(1)
	}
}
