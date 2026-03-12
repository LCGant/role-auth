# Auth Service

[Leia em Portugues](README.pt-BR.md) | [Project root](../../README.md)

`role-auth` is the identity service of the platform. It owns local credentials, sessions, device binding, MFA, OAuth login, password reset, and email verification.

## Core scope

- local registration and login
- opaque sessions with device-aware validation
- TOTP MFA and backup codes
- OAuth login and account linking
- email verification
- password reset
- internal session introspection for trusted callers

## Security model

The service is designed to be the source of truth for authentication state.

- sessions are opaque and stored hashed
- device tokens are separate from session tokens
- MFA and re-auth flows rotate or reissue session state where needed
- local accounts require email verification before becoming fully active
- internal endpoints are protected with dedicated internal tokens
- browser and non-browser flows are intentionally distinguished for CSRF handling

## Internal integrations

- sends verification and reset delivery requests to `notification`
- forwards audit events to `audit`
- serves session introspection to `pep` and trusted internal services

## Status

This service already covers the hard parts of an auth core and is a strong engineering starting point. It still needs production-specific integration work such as mature mail providers, operator workflows, and environment-specific rollout discipline.

## Notes for contributors

- treat this service as security-sensitive code
- prefer fail-closed behavior
- test auth, session, MFA, OAuth, and reset flows after every security-related change
- read `docs/SECURITY_INVARIANTS.md` before changing session or re-auth logic

