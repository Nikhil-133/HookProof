# Threat model

This document describes the assets, trust boundaries and attacker capabilities
that HookProof reasons about. It covers both the **lab under test** (a payment
webhook handler) and the **HookProof tooling itself**.

## 1. System overview

```text
+------------------+        signed HTTP         +----------------------+
|  Payment         |  ----------------------->  |  Webhook handler     |
|  provider        |    POST /webhooks/payment   |  (vulnerable/secure) |
+------------------+                            +----------+-----------+
                                                           |
                                              writes synthetic state
                                                           v
                                                +----------------------+
                                                |  SQLite application  |
                                                |  (orders, payments,  |
                                                |   idempotency keys)  |
                                                +----------+-----------+
                                                           ^
                                          read-only state  |
                                                           |
+------------------+        test token + loopback          |
|  HookProof       |  ------------------------------------+
|  scanner         |
+------------------+
```

## 2. Assets

| Asset | Why it matters |
| --- | --- |
| Protected business state | A payment/order must change exactly when a legitimate event is processed, and never otherwise. |
| Webhook signing secret | Forging it allows arbitrary events to be trusted. |
| Test-state token | Grants read access to internal application state. |
| Freshness window | Limits the useful lifetime of a captured signed event. |
| Idempotency ledger | Prevents duplicate deliveries from repeating a business operation. |

## 3. Trust boundaries

1. **Internet / provider → webhook handler.** The handler must authenticate
   every request before any business logic. The signed timestamp prevents replay
   outside the freshness window.
2. **Webhook handler → database.** Multiple deliveries can arrive concurrently.
   Authentication and idempotency must be enforced atomically.
3. **HookProof → test-state interface.** This interface is a test-only backdoor.
   It must require a separate token and must refuse non-loopback clients.
4. **HookProof → target selection.** By default, targets must be loopback. Any
   additional host must be explicitly allow-listed by the operator.

## 4. Attacker capabilities considered

| Capability | Example | Mitigation tested |
| --- | --- | --- |
| Send unauthenticated requests | Unsigned event | `missing_signature` |
| Forge or guess a signature | Random HMAC | `invalid_signature` |
| Modify a signed body | Change amount after signing | `payload_tampering` |
| Replay a captured event | Resend the same payload | `stale_timestamp` |
| Deliver the same event twice | Retry from provider | `duplicate_event` |
| Deliver the same event concurrently | Parallel retries | `concurrent_duplicate` |
| Reuse an event ID for a different order | Cross-order replay | `event_id_reuse` |
| Send an unsupported event type | `payment.refunded` | `unsupported_event_type` |
| Send invalid amounts / malformed JSON | Negative amount, broken body | `invalid_amount`, `malformed_payload` |

## 5. Security invariants

For each scenario HookProof asserts an *effect* invariant, not a status code:

- An unauthenticated or tampered event creates **zero** payments.
- A valid event creates **exactly one** payment for the expected amount.
- Repeated and concurrent deliveries of one event create **at most one** payment.
- An unsupported or invalid event changes **no** protected state.
- A state-observation failure is reported as `ERROR` (inconclusive), never as a
  pass.

## 6. Threats to HookProof itself

| Threat | Impact | Mitigation |
| --- | --- | --- |
| Scanning a third-party host | Unauthorised testing / legal risk | Loopback default allow-list; explicit `--allow-host` opt-in |
| Exposing the vulnerable lab | Remote attackers get an intentionally weak handler | `lab serve` refuses non-loopback binds |
| Test-state interface abuse | Internal state disclosure | Separate token + loopback-only enforcement |
| Secret leakage in reports | Credential compromise | Secrets are never serialised; only redacted markers appear |
| Malicious target responses | Injection into HTML/terminal output | HTML-escaped report rendering; Rich markup is not parsed from target data |
| Runaway scans | Resource exhaustion | Per-request timeout and `--max-requests` budget |

## 7. Non-goals and residual risk

- HookProof cannot detect vulnerabilities outside the modelled scenarios.
- Concurrent tests are probabilistic and may miss timing-dependent races.
- EffectProof depends on the target exposing trustworthy state. A malicious
  target could lie through its test interface.
- The vulnerable lab must never be deployed to a shared or public network.
- HookProof is not a substitute for a professional penetration test or code
  review.
