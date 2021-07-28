# VATUSA Unified Login Scheme v3

## About
Supporting OAuth2 Authorizator Grant w/ PKCE, PKCE is optional since many libraries don't support it ... yet. JWK supported key types, by the [upstream library](https://github.com/lestrrat-go/jwx).

| kty | Curve                   | Go Key Type                                   |
|:----|:------------------------|:----------------------------------------------|
| RSA | N/A                     | rsa.PrivateKey / rsa.PublicKey                |
| EC  | P-256<br>P-384<br>P-521<br>secp256k1     | ecdsa.PrivateKey / ecdsa.PublicKey            |
| oct | N/A                     | []byte                                        |
| OKP | Ed25519                 | ed25519.PrivateKey / ed25519.PublicKey        |
|     | X25519                  | (jwx/)x25519.PrivateKey / x25519.PublicKey    |

The purpose of this endpoint is to authenticate the identity of your visitor. Authorization is not provided by this service.

Based on [ZAU's OAuth2 Provider](https://github.com/vzau/sso) (https://github.com/vzau/sso).

## Clients Validated Against

Libraries tested against:
- https://github.com/thephpleague/oauth2-client [a custom client will be provided soon(TM)]
- https://www.npmjs.com/package/client-oauth2 [very messy test implementation: https://github.com/vzau/sso-test/]
- https://pkg.go.dev/golang.org/x/oauth2

We will provide implementation examples in due time.

## References utilized in creation of this Provider

References:
1. OAuth 2.0 Authorization Framework RFC6749 https://datatracker.ietf.org/doc/html/rfc6749
2. PKCE by OAuth Public Clients RFC7636 https://datatracker.ietf.org/doc/html/rfc7636
3. JSON Web Key (JWK) RFC7517 https://datatracker.ietf.org/doc/html/rfc7517
4. JSON Web Algorithms (JWA) RFC7518 https://www.rfc-editor.org/rfc/rfc7518.html
5. JSON Web Token (JWT) RFC7519 https://datatracker.ietf.org/doc/html/rfc7519