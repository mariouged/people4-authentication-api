# TEST

go test ./test/ -v

## Step 1 — Generate a test key pair (one-time)

ssh-keygen -t rsa -b 2048 -f test_key -N ""

## Step 2 — Register the public key

cat test_key.pub > authorized_keys

## Step 3 — Start the server (in one terminal)

export JWT_SECRET="a-strong-random-secret-at-least-32-chars"
go run main.go

## Step 4 — Connect and capture the JWT (in another terminal)

ssh -i test_key -p 2222 \
    -o StrictHostKeyChecking=no \
    -o PasswordAuthentication=no \
    test@currito

> Expected output:
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}

> Real output:
PTY allocation request failed on channel 0
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3ODI2MzEyMTYsImlzcyI6ImN1c3RvbS1zc2gtYXV0aC1zZXJ2ZXIiLCJzdWIiOiJ0ZXN0In0.hyJuRU-gWqZZW6rSaaWPwMJdPc1ZzXhygUtLUtOE_bs"}
Connection to currito closed.
