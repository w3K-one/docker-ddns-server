package nswrapper

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/labstack/gommon/log"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

// UpdateRecord builds a nsupdate file and updates a record by executing it with nsupdate.
func UpdateRecord(hostname string, target string, addrType string, zone string, ttl int, enableWildcard bool) error {
	log.Info(fmt.Sprintf("%s record update request: %s -> %s", addrType, hostname, target))

	f, err := ioutil.TempFile(os.TempDir(), "dyndns")
	if err != nil {
		return err
	}

	defer os.Remove(f.Name())
	w := bufio.NewWriter(f)

	w.WriteString(fmt.Sprintf("server %s\n", "localhost"))
	w.WriteString(fmt.Sprintf("zone %s\n", zone))
	w.WriteString(fmt.Sprintf("update delete %s.%s %s\n", hostname, zone, addrType))
	if enableWildcard {
		w.WriteString(fmt.Sprintf("update delete %s.%s %s\n", "*."+hostname, zone, addrType))
	}
	w.WriteString(fmt.Sprintf("update add %s.%s %v %s %s\n", hostname, zone, ttl, addrType, target))
	if enableWildcard {
		w.WriteString(fmt.Sprintf("update add %s.%s %v %s %s\n", "*."+hostname, zone, ttl, addrType, target))
	}
	w.WriteString("send\n")

	w.Flush()
	f.Close()

	cmd := exec.Command("/usr/bin/nsupdate", f.Name())
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("%v: %v", err, stderr.String())
	}

	if out.String() != "" {
		return fmt.Errorf("%s", out.String())
	}

	return nil
}

// DeleteRecord deletes a name and optionally its wildcard.
func DeleteRecord(hostname string, zone string, enableWildcard bool) error {
	return DeleteRecords([]string{hostname}, zone, enableWildcard)
}

// DeleteRecords removes related names in one atomic, single-zone DNS update.
func DeleteRecords(names []string, zone string, enableWildcard bool) error {
	script, err := deleteScript(names, zone, enableWildcard)
	if err != nil {
		return err
	}
	cmd := exec.Command("/usr/bin/nsupdate")
	cmd.Stdin = strings.NewReader(script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nsupdate: %w: %s", err, output)
	}
	if len(output) != 0 {
		return fmt.Errorf("nsupdate: %s", output)
	}
	return nil
}

func deleteScript(names []string, zone string, wildcard bool) (string, error) {
	valid := func(s string) bool { return s != "" && !strings.ContainsAny(s, " \t\r\n;\\\"") }
	if !valid(zone) {
		return "", fmt.Errorf("invalid zone")
	}
	var script strings.Builder
	fmt.Fprintf(&script, "server localhost\nzone %s\n", zone)
	for _, name := range names {
		if !valid(name) {
			return "", fmt.Errorf("invalid name")
		}
		fmt.Fprintf(&script, "update delete %s.%s\n", name, zone)
		if wildcard {
			fmt.Fprintf(&script, "update delete *.%s.%s\n", name, zone)
		}
	}
	script.WriteString("send\n")
	return script.String(), nil
}
