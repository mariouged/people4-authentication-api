# authentication api

develop an open ssh server that the client send the id_rsa.pub and the ssh server response and json web token

you need to build a custom SSH server using an SSH library rather than using the standard OpenSSH daemon (sshd). Standard OpenSSH does not natively exchange public keys for JSON Web Tokens (JWTs) during the authentication handshake.

can implement this pattern by writing a custom SSH server in a language like Go (using the crypto/ssh package)

## Architectural Workflow

1. Connection: The client initiates an SSH connection.

2. Public Key Submission: The client offers its public key (id_rsa.pub) to authenticate.

3. Verification: The server validates the public key against a database or registry.

4. JWT Generation: If valid, the server generates a signed JWT.

5. Token Delivery: The server sends the JWT back to the client, usually via a custom subsystem, environment variable, or a banner message, and then closes the connection.

