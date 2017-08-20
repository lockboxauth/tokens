# tokens

The `tokens` package encapsulates the part of the [auth system](https://impractical.co/auth) that handles issuing and validating refresh tokens.

## Implementation

Tokens consist of an ID, the profile they correspond to, the scopes that the token has access to, whether the token has been revoked or used yet, and some metadata about its creation. Tokens are only usable once.

## Place in the Architecture

Tokens are a method of obtaining a grant using the [`grants` system](https://impractical.co/auth/grants). That grant can then be traded for a new access token and a new refresh token, to keep their session alive.

Whenever a grant is issued, it should create a new access token using the [`sessions` system](https://impractical.co/auth/sessions) and a refresh token using the `tokens` system. The user then keeps both of those tokens, using the access token to authenticate future requests for their data. When the access token expires, the refresh token should be used as a new grant source to obtain a new grant, which in turn is exchanged for a new access token and refresh token, keeping the cycle going.

## Scope

`tokens` is solely responsible for issuing refresh tokens as part of a session and validating them. The HTTP handlers it provides are responsible for verifying the authentication and authorization of the requests made against it, which will be coming from untrusted sources.

The questions `tokens` is meant to answer for the system include:

  * Is this a valid refresh token?
  * For which profile should an access token be issued when this refresh token is redeemed? And for which profile?
  * What refresh tokens does a user have floating around right now, unused?

The things `tokens` is explicitly not expected to do include:

  * Manage valid scopes.
  * Generate or validate access tokens.
  * Understand scopes, clients, or profiles beyond opaque IDs to be passed through transparently.
