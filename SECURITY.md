# Security Policy

## Scope

The `chain-payments` binary and image. Out of scope: the Move package, the SDK and kit (their own policies), full nodes and
price sources.

## Model

1. **Payments are verified on-chain** by digest: effects succeeded and the package's `Paid` event matches the quote
   (merchant object, session, nonce, coin type, amount). A session is paid once.
2. **Quotes are bounded**: signed for 120 seconds, single-use nonces enforced on-chain, minimum amounts per coin on-chain.
3. **No quote without agreeing prices** from independent public sources.
4. **Secrets**: the quote and webhook keys are separate seed files; API keys are stored hashed; nothing secret is logged
   or returned. Database TLS is `verify-full` only.
5. **Exposure**: only the session endpoints are public; the merchant API and metrics listen on a separate port meant to stay
   inside the cluster. CORS is limited to configured origins; responses set no cookie.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository. Please do not open a public issue.
