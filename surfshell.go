package surfshell

import (
	"bufio"
	"errors"
	"regexp"
	"strings"
	"time"

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
func (surfusShell SurfusShell) Expect(match string, timeout time.Duration) (string, error) {
	var output = ""
	var startTime = time.Now().UnixNano()
	for strings.Contains(output, match) == false {
		if surfusShell.reader.Buffered() > 0 {

			if time.Now().UnixNano()-startTime >= timeout.Nanoseconds() {
				return "", errors.New("Timeout when attempting to get " + match)
			}

			character, _, err := surfusShell.reader.ReadRune()
			if err != nil {
				return "", err
			}
			output = output + string(character)
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}

	return output, nil
}

// ExpectRegex reads data from a buffer until a regex expression is matched.
func (surfusShell SurfusShell) ExpectRegex(regex string, timeout time.Duration) (string, error) {
	var output = ""
	var matched = false
	var startTime = time.Now().UnixNano()

	for matched == false {
		matched, err := regexp.MatchString(regex, output)

		if err != nil {
			return "", err
		}

		if matched {
			return output, nil
		}

		if time.Now().UnixNano()-startTime >= timeout.Nanoseconds() {
			return "", errors.New("Timeout when attempting to get " + regex)
		}

		if surfusShell.reader.Buffered() > 0 {
			character, _, err := surfusShell.reader.ReadRune()
			if err != nil {
				return "", err
			}
			output = output + string(character)
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}

	return output, nil
}

// ShellConnect creates an SSH connection to a device and opens up a terminal. This will automatically answer any KeyboardInteractiveChallenges with autoAnswerChallenge
func (surfusShell *SurfusShell) ShellConnect(host, user, pass string, autoAnswerChallenge string) error {
	return surfusShell.ShellConnectInteractive(host, user, pass, func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		// Just send the password back for all questions
		answers := make([]string, len(questions))
		for i := range answers {
			answers[i] = pass
		}
		return answers, nil
	})
}

// ShellConnectInteractive creates an SSH connection to a device and open up a terminal. This method allows you to provide your own KeyboardInteractiveChallenge
func (surfusShell *SurfusShell) ShellConnectInteractive(host, user, pass string, challenge ssh.KeyboardInteractiveChallenge) error {
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
	if surfusShell.session != nil {
		surfusShell.session.Close()
	}

	if surfusShell.client != nil {
		surfusShell.client.Close()
	}
}
