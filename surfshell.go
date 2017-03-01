package surfshell

import (
	"bufio"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SurfusShell contains the SSH data
type SurfusShell struct {

	// The connection representing the SSH Client
	client *ssh.Client

	// The session information relating to the client
	session *ssh.Session

	// The stream to read input
	reader *bufio.Reader

	// The stream to read output
	writer *bufio.Writer
}

// WriteLine writes a string with a line terminator
func (surfusShell SurfusShell) WriteLine(text string) error {
	_, err := surfusShell.writer.WriteString(text + "\r")
	surfusShell.writer.Flush()
	return err
}

// Write writes a string
func (surfusShell SurfusShell) Write(text string) error {
	_, err := surfusShell.writer.WriteString(text)
	surfusShell.writer.Flush()
	return err
}

// Read reads a single character
func (surfusShell SurfusShell) Read() (rune, error) {
	runeValue, _, err := surfusShell.reader.ReadRune()
	if err != nil {
		return 0, err
	}
	return runeValue, nil
}

// Expect reads data from a buffer until a string is matched.
func (surfusShell SurfusShell) Expect(match string) string {
	var output = ""
	for strings.Contains(output, match) == false {
		character, _, _ := surfusShell.reader.ReadRune()
		output = output + string(character)
	}

	return output
}

// ExpectRegex reads data from a buffer until a regex expression is matched.
func (surfusShell SurfusShell) ExpectRegex(regex string) string {
	var output = ""
	var matched = false
	for matched == false {
		matched, _ = regexp.MatchString(regex, output)
		character, _, _ := surfusShell.reader.ReadRune()
		output = output + string(character)
	}

	return output
}

// ShellConnect creates an SSH connection to a device and open up a terminal
func (surfusShell *SurfusShell) ShellConnect(host, user, pass string, challenge ssh.KeyboardInteractiveChallenge) error {
	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(pass), ssh.KeyboardInteractive(challenge)},
	}

	sshConfig.Ciphers = []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "arcfour256", "arcfour128", "aes-128cbc", "3des-cbc"}

	client, err := ssh.Dial("tcp", host, sshConfig)
	surfusShell.client = client

	if err != nil {
		return err
	}

	session, err := client.NewSession()
	surfusShell.session = session
	if err != nil {
		client.Close()
		return err
	}

	err = session.RequestPty("SurfusSSH", 800, 240, nil)
	if err != nil {
		session.Close()
		client.Close()
		return err
	}

	stdinBuf, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		return err
	}

	stdoutBuf, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		client.Close()
		return err
	}

	surfusShell.reader = bufio.NewReader(stdoutBuf)
	surfusShell.writer = bufio.NewWriter(stdinBuf)

	err = session.Shell()
	if err != nil {
		session.Close()
		client.Close()
		return err
	}

	return nil
}

// Close will disconnect from the Client
func (surfusShell SurfusShell) Close() {
	surfusShell.client.Close()
	surfusShell.session.Close()
}
