package main

import (
	"log"
	"os"
)

var infoLogger = log.New(os.Stdout, "INFO: ", log.LstdFlags)
var errLogger = log.New(os.Stderr, "ERROR: ", log.LstdFlags)
var fatalLogger = log.New(os.Stderr, "FATAL: ", log.LstdFlags)
