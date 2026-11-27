# Where in Russia · transparency

Public, append-only record of the signed daily checkpoints of [Where in Russia](https://whereinrussia.com) task receipts.
This repository holds verification material only: no platform code, no private keys, no customer data.

## What is here

| Path | Content |
|---|---|
| `checkpoints/YYYY/DAY.json` | The checkpoint as signed by the service: Merkle root (RFC 6962) of the day's receipts, tree size, previous checkpoint digest, Ed25519 signature |
| `keys/jwks.json` | The service's public keys with their status: current, retired (still valid for old receipts) or revoked |
| `witnesses/DAY/` | The Sigstore Rekor bundle and the one-time public key used to enter the checkpoint in Rekor's public log |
| `index.json` | Every checkpoint with its root and digest, in order |
| `tools/verify.mjs` | Standalone verifier (WebCrypto, no dependencies) |

## How to verify without trusting the service

1. **Signature.** Remove `signature` and `digest` from a checkpoint and serialise the rest as canonical JSON (object keys sorted, no whitespace). Verify the Ed25519 signature with the key in `keys/jwks.json` whose `kid` matches `signed.kid`.
2. **Chain.** Each checkpoint names the digest of the one before (`prev`). A rewritten past day breaks the chain, and this repository's git history shows any change.
3. **Time.** `witnesses/DAY/rekor.bundle` is a Sigstore Rekor entry for the checkpoint file. Rekor is an independent, public, append-only log, and its integration time proves the checkpoint existed then: `cosign verify-blob --key witnesses/DAY/cosign.pub --bundle witnesses/DAY/rekor.bundle checkpoints/YYYY/DAY.json`. The Rekor key is used once and proves time only, not identity.
4. **A receipt.** `node tools/verify.mjs receipt.json` checks a receipt's signature, fetches its inclusion proof from `https://whereinrussia.com/api/transparency/proof/{id}` and recomputes the root.

## What this does not prove

The checkpoints prove the **integrity** of what the service signed and **when** it existed. They do not prove that the figures are **factually right**: every figure carries its own source, date and status. They do not prove the **legal identity** of the service: a key shows who holds it. The seller is named on https://whereinrussia.com/terms/.

_Updated automatically by wir-transparency-bot._
