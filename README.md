# CRL Based TLS Client Certificate Revokation Checker Traefik Plugin

`tlscrlchecker` is a Traefik middleware plugin designed to enhance security by verifying the revocation status of client certificates. It uses a Certificate Revocation List (CRL) to ensure that any client certificates that have been revoked cannot access protected services.

## How It Works

1. The plugin intercepts requests that use TLS and checks if a client certificate is presented.
2. It loads the CRL from the specified file and validates the presented client certificate against the list of revoked certificates.
3. If the certificate is revoked, the plugin blocks the request with a 400 Bad Request error. Otherwise, the request is passed to the next middleware or service in the chain.


## Installation & Test

A sample is provided in the test folder. You can use it to test the plugin in a controlled environment.




