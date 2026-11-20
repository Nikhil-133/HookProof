# Security policy

HookProof is a **defensive security testing tool**. It is intended for testing
webhook handlers that you own or are explicitly authorised to test.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

This is an educational MVP. Security fixes are applied to the latest release on
`main`.

## Reporting a vulnerability

Please **do not** open a public issue for a security bug.

Report it privately through GitHub's
[security advisory feature](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
for this repository. Include:

- the affected version or commit,
- a description of the issue and its impact,
- minimal reproduction steps,
- any suggested fix.

You can expect an acknowledgement within a few days. This project is maintained
by a single author, so timelines are best-effort.

## Scope

In scope:

- signature verification and replay-protection bypasses in the **secure** lab,
- state-inspection authentication or loopback-enforcement bypasses,
- report redaction failures (secrets leaking into JSON or HTML output),
- denial-of-service issues in the scanner or lab,
- dependency vulnerabilities with a realistic exploit path.

Out of scope:

- the **vulnerable** lab behaving insecurely. That mode is intentionally broken;
  it is the test fixture, not a bug. It must only run on loopback.
- findings produced by scanning a target you do not own,
- social engineering, physical access, or issues requiring a compromised host.

## Safe-use rules

1. **Only scan systems you own or have written permission to test.** The
   loopback allow-list is a technical safety rail, not legal authorisation.
2. **Never expose the vulnerable lab** beyond an isolated local machine. It
   accepts unsigned events by design.
3. **Treat secrets as secrets.** Use `.env` (gitignored) or environment
   variables. Never commit real webhook secrets or API tokens.
4. **Use synthetic data.** HookProof is not connected to a real payment
   processor and never should be.

## What HookProof does not protect against

- It does not prove a handler is safe; it proves that the tested scenarios were
  handled correctly under the observed conditions.
- Concurrency testing is probabilistic, not exhaustive.
- EffectProof requires a reachable, token-protected state interface. Without one,
  internal effects cannot be verified.
