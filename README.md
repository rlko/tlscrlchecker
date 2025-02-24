# CRL Based TLS Client Certificate Revocation Checker Traefik Plugin

`tlscrlchecker` is a Traefik middleware plugin designed to enhance security by verifying the revocation status of client certificates. It uses a Certificate Revocation List (CRL) to ensure that any client certificates that have been revoked cannot access protected services.

## How It Works

1. The plugin intercepts requests that use TLS and checks if a client certificate is presented.
2. It loads the CRL from the specified file and validates the presented client certificate against the list of revoked certificates.
3. If the certificate is revoked, the plugin blocks the request with a 400 Bad Request error. Otherwise, the request is passed to the next middleware or service in the chain.


## Installation & Test

A sample is provided in the test folder. You can use it to test the plugin in a controlled environment.


## Configuration

### Static configuration
```yaml
experimental:
  plugins:
    tlscrlchecker:
      moduleName: "github.com/Miladbr/tlscrlchecker"
```

### Dynamic configuration

* TOML configuration

```toml
[http]
[http.middlewares]
  [http.middlewares.my-tlscrlchecker.plugin.tlscrlchecker]
    crlFilePath = "/pki/crl/crl.pem" # Supports both PEM and DER formats
```

* YAML configuration

```yaml
http:
  middlewares:
    my-tlscrlchecker:
      plugin:
        tlscrlchecker:
          crlFilePath: "/pki/crl/crl.pem" # Supports both PEM and DER formats
```


