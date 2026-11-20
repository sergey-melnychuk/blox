# Security

Blox has not had a security audit yet. Use it on test networks with test funds only.

## Reporting a vulnerability

Report it privately through GitHub: the repository's **Security** tab, then **Report a
vulnerability**. Please don't open a public issue, pull request or discussion for it.

Include what is affected (the Android app, the relay, the web SDK, the Rust crates or the
protocol in BLOX.md), the version or commit, the steps to reproduce, and what an attacker
gains.

## Scope

In scope: anything that lets someone other than the phone's owner sign or send, change what
the phone shows from what it signs, read request contents or link separate signers through
the relay, or take keys from the phone or the browser beyond what BLOX.md says is
unprotected (§9.6).

Out of scope: the limits BLOX.md already states, such as what the relay, connected sites and
the chosen endpoint learn and phishing pages that show a real site's QR code (§3.3), what is
trusted (§3.4) or out of scope (§3.5), and denial of service against the public relay at
`relay.example.com`.
