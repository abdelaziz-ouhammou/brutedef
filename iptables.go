package main

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// iptablesBlocker is responsible for blocking malicious IP addresses.
type iptablesBlocker struct {
	badIPChannel chan net.IP
	errChannel   chan error
	blockedIPs   map[string]struct{}
}

// creates a new iptablesBlocker. badIPChannel will be used to for
// receiving malicious IP addresses. errChannel will be used for sending
// errors

func NewIPtablesBlocker(badIPChannel chan net.IP,
	errChannel chan error) (*iptablesBlocker, error) {

	infoLogger.Println("checking if iptables is installed...")
	cmd := exec.Command("iptables", "--version")
	_, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	infoLogger.Println("checking if ipset is installed...")
	cmd = exec.Command("ipset", "--version")
	_, err = cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	infoLogger.Println("creating ipset badips ...")
	cmd = exec.Command("ipset", "create", "badips", "iphash")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if !strings.Contains(string(output), "already exists") {
			return nil, fmt.Errorf("%w: %s", err, string(output))
		}
	}

	infoLogger.Println("creating iptables blocking rule ...")
	cmd = exec.Command("iptables", "-t", "raw", "-I", "PREROUTING", "-m", "set", "--match-set", "badips", "src", "-j", "DROP")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, string(output))
	}
	return &iptablesBlocker{
		badIPChannel: badIPChannel,
		errChannel:   errChannel,
		blockedIPs:   map[string]struct{}{},
	}, nil
}

// creates a new iptablesBlocker. badIPChannel will be used to for
// receiving malicious IP addresses. errChannel will be used for sending
// errors
func (b iptablesBlocker) startBlockingIPs() {
	for ip := range b.badIPChannel {
		if _, ok := b.blockedIPs[ip.String()]; ok {
			continue
		}
		err := b.blockIP(ip)
		if err != nil {
			b.errChannel <- err
			return
		}
		blockedIPs[ip.String()] = struct{}{}
	}
}

// blocks an IP address by adding it to "badips" ipset.
func (b iptablesBlocker) blockIP(ip net.IP) error {
	cmd := exec.Command("ipset", "add", "badips", ip.String())
	infoLogger.Printf("blocking ip %s\n", ip.String())
	_, err := cmd.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if strings.Contains(string(exitError.Stderr), "already added") {
				return nil
			}
			return errors.New(string(exitError.Stderr))
		}
		return err
	}
	return nil
}
