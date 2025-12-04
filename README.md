openssl req -new -x509 -keyout key.pem -out cert.pem -days 365 -nodes

curl.exe -k -X POST https://127.0.0.1:4443 -d "Hello secure world"

