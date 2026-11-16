# Protocol model

This is the model an external reviewer can check. It is not that review.
`pm-encryption vectors` prints the bytes a second implementation has to match.
The committed copy is `tests/vectors/kat.v1.json`.

## Channel

`SecureChannel` has one transmit key and one receive key for the process.
`k_channel_ratchet` is false. A copy of either key decrypts every frame in
that direction. The channel does not store history. Callers that need a
transcript keep it somewhere else.

Frames are `PME2` version 1, XChaCha20-Poly1305, with a random 24-byte nonce.
The first accepted sequence is 0. A higher sequence before that is `stale`
and does not move the window. After 0, 64 frames may arrive out of order.
A failed open does not move the window.

Unauthenticated `crypto_kx` is a separate build feature. It does not pin an
identity. The authenticated path below is the one this model describes.

## Handshake

Peers pin each other's Ed25519 key before message 1. The handshake does not
discover trust. Identities are in the clear. The wire domain is
`pm.encryption.handshake.sigma-i.v1`. That name is not SIGMA identity
protection.

Messages:

1. initiator identity, initiator X25519 ephemeral, session id
2. responder identity, responder X25519 ephemeral, responder signature
3. initiator signature

The signed transcript is the domain string, version, suite, context length
and context, session id, both identities, both ephemerals, then a role byte
(`1` initiator, `2` responder). A context swap or an identity swap fails
the signature.

Channel keys are HKDF-SHA256 of the `crypto_kx` output. The salt is
BLAKE2b-256 of the transcript without the role byte. The info strings are
`pm.encryption.channel.i2r.v1` and `pm.encryption.channel.r2i.v1`. After the
handshake, frame AAD uses that 32-byte hash as the context.

The initiator derives keys while writing message 3. The responder derives
keys only after message 3 verifies. Callers send application data only after
both sides report complete.

## Files

The Ed25519 identity signs the manifest. It does not open the content key.
Each device has a separate X25519 `FileKey`. `crypto_box` seals one random
content key to each recipient file key. The manifest carries the sender's
file public key and is signed by the Ed25519 identity. The signature covers
a hash of the recipient seals.

Chunk nonce is transfer id, revision, and index. `create_file_offer` mints
a new content key, encrypts each index once, and wipes the key before it
returns. `reseal_file_chunk` refuses a second plaintext at an index.
`FileInbox::accept` treats a second ciphertext at an accepted index as a
replay.

A later revision that omits a recipient does not make an older ciphertext
unreadable. Member removal is not file revocation.

`FileSnapshot` wipes its plaintext when it is destroyed. A caller that
writes staging pieces deletes them after the verified file is published.
The shared mount holds ciphertext.

## Out of this model

- the signal text room, which is a separate policy over libsignal 0.108.0 and is not this channel
- MLS
- a listening broker, a tailnet address, or a P2P path
- Linux and Android, which this tree has not built
