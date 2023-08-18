package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
)

// journalWatcher is responsible for attaching to and reading from journalctl
// badIPChannel is used for sending IPs to be blocked
// errChannel is for unrecoverable errors
// threshold is the number of times an IP will showup before it's blocked
// badIPCount maintains a count for all IPs encountered
type journalWatcher struct {
	badIPChannel chan net.IP
	errChannel   chan error
	threshold    int
	badIPCount   map[string]int
}

// Returns a new journal watcher.
func NewJournal(badIPChannel chan net.IP,
	errChannel chan error, threshold int) *journalWatcher {
	return &journalWatcher{
		badIPChannel: badIPChannel,
		errChannel:   errChannel,
		threshold:    threshold,
		badIPCount:   map[string]int{},
	}
}

// executes the command "journalctl -f -u ssh -n 0 -o cat" and attaches to
// stdout and stderr
func (j journalWatcher) Run() {
	command := exec.Command("journalctl", "-f", "-u", "ssh", "-n", "0", "-o", "cat")
	stdout, err := command.StdoutPipe()
	if err != nil {
		j.errChannel <- err
		return
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		j.errChannel <- err
		return
	}
	err = command.Start()
	if err != nil {
		j.errChannel <- err
		return
	}
	go j.StartParser(stdout)
	go j.ListenForErrors(stderr)

	err = command.Wait()
	if err != nil {
		j.errChannel <- err
		return
	}
}

// read new lines from journal and parse IP addresses
// keep a count of each time an IP address is encountered in badIPCount
// when the count reaches a threshold send the ip through badIPChannel to be blocked.
func (j journalWatcher) StartParser(stdoutPipe io.Reader) {
	scanner := bufio.NewScanner(stdoutPipe)
	for scanner.Scan() {
		if !strings.Contains(scanner.Text(), "Failed password") {
			continue
		}
		ip, err := j.parseIP(scanner.Text())
		if err != nil {
			errLogger.Println(err)
			continue
		}
		j.badIPCount[ip.String()] += 1
		if j.badIPCount[ip.String()] >= j.threshold {
			j.badIPChannel <- ip
			delete(j.badIPCount, ip.String())
		}
	}
	close(j.badIPChannel)
	j.errChannel <- fmt.Errorf("journalctl stdout pipe closed err: %w", scanner.Err())
}

// listens for errors from journalctl command
func (j journalWatcher) ListenForErrors(stderr io.Reader) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		j.errChannel <- errors.New(scanner.Text())
		return
	}
	close(j.badIPChannel)
	j.errChannel <- fmt.Errorf("journalctl stderr pipe closed err:%w", scanner.Err())
}

// parses ip address from each line
func (j journalWatcher) parseIP(line string) (net.IP, error) {
	parts := strings.Split(line, " ")
	var ipComing = false
	for _, p := range parts {
		if ipComing {
			ip := net.ParseIP(p)
			if ip == nil {
				return nil, fmt.Errorf("failed to parse %s as an IP", p)
			}
			return ip, nil
		}
		if p == "from" {
			ipComing = true
		}
	}
	return nil, fmt.Errorf("ip not found in line '%s'", line)
}
