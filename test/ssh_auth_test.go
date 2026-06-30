package test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)

// serverAddr returns the SSH server address from SSH_SERVER_ADDR env or the default.
func serverAddr() string {
	if addr := os.Getenv("SSH_SERVER_ADDR"); addr != "" {
		return addr
	}
	return "localhost:2222"
}

// dial connects to the SSH server using signer and returns the raw output written
// by the server on the session channel.
func dial(t *testing.T, signer ssh.Signer) []byte {
	t.Helper()

	cfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}

	client, err := ssh.Dial("tcp", serverAddr(), cfg)
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer session.Close()

	out, err := session.Output("")
	if err != nil && err != io.EOF {
		t.Fatalf("session output: %v", err)
	}
	return out
}

// TestSSHAuthReturnsJWT authenticates with test/test_key (which must be listed
// in db/authorized_keys) and asserts a non-empty JWT is returned.
//
// Prerequisites:
//   - Server running: go run .
//   - JWT_SECRET env var set for the server process.
//   - test/test_key.pub content present in db/authorized_keys.
//   - test/test_key private key file present (generate once with:
//     ssh-keygen -t rsa -b 2048 -f test/test_key -N "")
//
// Run: go test ./test/ -v
func TestSSHAuthReturnsJWT(t *testing.T) {
	keyPEM, err := os.ReadFile("test_key.priv")
	if err != nil {
		t.Fatalf("read test_key.priv: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse test_key: %v", err)
	}

	out := dial(t, signer)

	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal response %q: %v", string(out), err)
	}
	if resp.Token == "" {
		t.Fatal("expected a non-empty JWT, got empty string")
	}
	t.Logf("received JWT: %s", resp.Token)
}

// TestSSHAuthRejectsUnknownKey verifies that an unregistered key is rejected.
func TestSSHAuthRejectsUnknownKey(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	cfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}

	_, err = ssh.Dial("tcp", serverAddr(), cfg)
	if err == nil {
		t.Fatal("expected connection to be rejected for unknown key, but it succeeded")
	}
	t.Logf("correctly rejected: %v", err)
}
