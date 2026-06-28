package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ssh"
)

const hostKeyPath = "host_key"

func getJWTSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET environment variable is not set")
	}
	return []byte(secret)
}

// loadOrGenerateHostKey loads the host key from disk, or generates and persists
// a new one if it does not exist. Persisting the key prevents clients from
// seeing "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!" on every restart.
func loadOrGenerateHostKey() (ssh.Signer, error) {
	keyBytes, err := os.ReadFile(hostKeyPath)
	if err == nil {
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse host key: %w", err)
		}
		return signer, nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read host key file: %w", err)
	}

	// No key on disk — generate a new one and save it.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate host key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err := os.WriteFile(hostKeyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to save host key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer from host key: %w", err)
	}
	return signer, nil
}

func main() {
	jwtSecret := getJWTSecret()

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// 1. Validate the key against your registry / database.
			if !isValidClientKey(key) {
				return nil, fmt.Errorf("unauthorized public key")
			}

			// 3. Generate the JWT.
			tokenString, err := generateJWT(conn.User(), jwtSecret)
			if err != nil {
				return nil, fmt.Errorf("failed to generate token: %w", err)
			}

			// 4. Carry the JWT into the session via Permissions.Extensions.
			return &ssh.Permissions{
				Extensions: map[string]string{
					"jwt": tokenString,
				},
			}, nil
		},
	}

	hostKey, err := loadOrGenerateHostKey()
	if err != nil {
		log.Fatalf("Host key error: %v", err)
	}
	config.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", "0.0.0.0:2222")
	if err != nil {
		log.Fatalf("Failed to listen on port 2222: %v", err)
	}
	defer listener.Close()

	log.Println("SSH authorization server running on port 2222...")

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(nConn, config)
	}
}

func generateJWT(username string, secret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": username,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iss": "custom-ssh-auth-server",
	})
	return token.SignedString(secret)
}

// isValidClientKey checks whether the supplied public key is authorized.
// It reads from the file defined by AUTHORIZED_KEYS_FILE (default: authorized_keys).
// Replace with a real database lookup for production use.
func isValidClientKey(incoming ssh.PublicKey) bool {
	path := os.Getenv("AUTHORIZED_KEYS_FILE")
	if path == "" {
		path = "authorized_keys"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Could not read authorized keys file %q: %v", path, err)
		return false
	}
	// ssh.ParseAuthorizedKey handles comments and options correctly;
	// we compare raw key bytes so the comment field is ignored.
	rest := data
	for len(rest) > 0 {
		pubKey, _, _, remaining, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			break
		}
		rest = remaining
		if bytes.Equal(pubKey.Marshal(), incoming.Marshal()) {
			return true
		}
	}
	return false
}

func handleConnection(nConn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("SSH handshake failed from %s: %v", nConn.RemoteAddr(), err)
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Failed to accept channel: %v", err)
			return
		}

		go func(ch ssh.Channel, reqs <-chan *ssh.Request) {
			defer ch.Close()
			for req := range reqs {
				if req.Type == "shell" || req.Type == "exec" {
					if err := req.Reply(true, nil); err != nil {
						log.Printf("Failed to reply to %s request: %v", req.Type, err)
						return
					}

					token := sshConn.Permissions.Extensions["jwt"]
					resp, _ := json.Marshal(map[string]string{"token": token})
					resp = append(resp, '\n')

					if _, err := ch.Write(resp); err != nil {
						log.Printf("Failed to write token to channel: %v", err)
					}
					return
				}
				if err := req.Reply(false, nil); err != nil {
					log.Printf("Failed to reply to %s request: %v", req.Type, err)
				}
			}
		}(channel, requests)
	}
}
