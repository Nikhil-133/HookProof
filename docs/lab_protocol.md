# HookProof lab protocol

Both lab modes (`vulnerable` and `secure`) implement exactly the same interface.
Only the *security behaviour* differs.

## 1. Payment webhook

`POST /webhooks/payment`

### Headers

| Header | Required | Description |
| --- | --- | --- |
| `Content-Type` | yes | `application/json` |
| `X-HookProof-Signature` | secure only | `sha256=<hex HMAC-SHA256>` |
| `X-HookProof-Timestamp` | secure only | Unix seconds used in the signing string |

### Signing string

```
<timestamp-as-ascii-decimal> + "." + <raw request body bytes>
```

`signature = HMAC_SHA256(secret, signing_string)` rendered as lowercase hex and
prefixed with `sha256=`.

The timestamp is part of the signed bytes, binding it to the body. A captured
signature therefore cannot be replayed with a freshly chosen timestamp.

### Body

```json
{
  "event_id": "evt-...",
  "type": "payment.succeeded",
  "order_id": "ord-...",
  "amount": 1000,
  "currency": "usd",
  "timestamp": 1730000000
}
```

Required fields: `event_id`, `type`, `order_id`, `amount`, `currency`, `timestamp`.
`amount` must be a positive integer, `currency` a 3-letter code, and the body
`timestamp` must equal the authenticated header timestamp in secure mode.

### Responses

| Status | Meaning |
| --- | --- |
| `200` | processed (or safely recognised duplicate) |
| `400` | invalid JSON |
| `401` | missing/invalid signature or stale timestamp |
| `422` | payload validation failure |

## 2. Mode behaviour

| Check | Vulnerable | Secure |
| --- | --- | --- |
| Signature verification | skipped | constant-time HMAC verification |
| Timestamp freshness | skipped | enforced (`HOOKPROOF_FRESHNESS_WINDOW`) |
| Payload validation | shallow | full |
| Duplicate events | every delivery applied | idempotent via unique event ID |
| Concurrent deliveries | raceable | `BEGIN IMMEDIATE` + unique constraint |

## 3. Restricted test-state interface

All endpoints below require `X-HookProof-Test-Token` and a **loopback** client.
Otherwise they return `401`/`403`.

| Method | Path | Response |
| --- | --- | --- |
| `GET` | `/__test__/health` | `{"status":"ok","mode":...,"secure":...}` |
| `GET` | `/__test__/orders/{order_id}` | `found`, `payment_count`, `amount_total`, `status`, `processed_event_ids` |
| `GET` | `/__test__/state` | aggregate `orders`/`payments`/`events` counters |
| `POST` | `/__test__/reset` | clear all synthetic data |

`payment_count` is the number of protected business operations (fulfilled
payments) recorded for an order. This is what EffectProof uses to judge a test
rather than the HTTP status code.

## 4. Data model

```text
orders(order_id PK, amount_total, status, created_at)
payments(id PK, order_id, event_id, amount, created_at)   # one row = one business operation
processed_events(event_id PK, order_id, processed_at)     # idempotency ledger
```

In secure mode a unique index on `payments(event_id)` provides defence in depth
alongside the `processed_events` primary key.
