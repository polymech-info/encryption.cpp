# Protocol model

This is the byte-level model of the three profiles this library implements.
It is not an external review. `pm-encryption vectors` and
`tests/vectors/kat.v1.json` lock the channel handshake, one `PME2` frame, and
one file offer. They do not replace the layouts below. The datagram profile
is specified here and is not in that vector file.

Integers are big-endian. A length prefix is the only delimiter. Domain
strings are the raw characters, without a trailing NUL. A parser that sees
the wrong magic, version, suite, or length rejects the message. A handshake
parser that rejects also enters `Failed` and drops the ephemeral secret.
There is no trailing-byte tolerance on the three handshake messages: the
size must be exact.

The profiles do not share a wire format. They share identity types, opaque
bytes, and typed errors. None of them interprets a MIME type, an extension,
or a codec.

| Profile | Entry | Wire |
|---|---|---|
| Channel | `Handshake`, then `SecureChannel` | `PMEH` then `PME2/v1` |
| Artifact | `FileOffer`, `FileInbox` | `PMFO` / `PMFM` / `PMFK` |
| Datagram | `SecureFlow` | `PMD1/v1` |

`SecureFlow::open_flow` opens a datagram. A reliable or durable request
returns `InvalidArgument`. It does not fall back to another profile.

## Channel

### Handshake messages

Peers pin each other's Ed25519 public key before message 1. The handshake
does not discover trust. Identities travel in the clear. The wire label
`pm.encryption.handshake.sigma-i.v1` is the transcript domain. It is not
SIGMA identity protection.

Every message starts with `PMEH`, version `1`, suite `1`, then a type byte
(`1`, `2`, or `3`).

| Message | After the 7-byte header | Size |
|---|---|---|
| 1 | session id 16, initiator Ed25519 32, initiator X25519 32 | 87 |
| 2 | session id 16, responder Ed25519 32, responder X25519 32, responder signature 64 | 151 |
| 3 | session id 16, initiator signature 64 | 87 |

Message 1 is unsigned. Message 2 and message 3 are signed. A zero session
id, a zero ephemeral, a session mismatch, or an identity that differs from
the pin is a failure. The same local and peer identity is rejected before
message 1.

### Signed transcript

The key transcript, in order:

1. `pm.encryption.handshake.sigma-i.v1`
2. version `1`, suite `1`
3. context length as `u32`, then the context bytes (1 to 4096)
4. session id 16
5. initiator Ed25519 32, responder Ed25519 32
6. initiator X25519 32, responder X25519 32

The signature covers that transcript plus one role byte: `1` for the
initiator, `2` for the responder. The salt used for key derivation is
BLAKE2b-256 over the transcript without the role byte
(`crypto_generichash`, 32 bytes, no key).

### Key derivation

`crypto_kx` runs first. The initiator calls
`crypto_kx_client_session_keys`. The responder calls
`crypto_kx_server_session_keys`. In libsodium those outputs match across
the two roles: the initiator's transmit key is the responder's receive key,
and the initiator's receive key is the responder's transmit key.

Each direction is then passed through HKDF-SHA256. The salt is the 32-byte
transcript hash. Extract uses that salt and the 32-byte `crypto_kx` output
as input keying material. Expand uses the info string with no trailing NUL
and writes 32 bytes.

| Direction | `crypto_kx` input | HKDF info |
|---|---|---|
| Initiator to responder | initiator transmit, which is the responder receive | `pm.encryption.channel.i2r.v1` |
| Responder to initiator | initiator receive, which is the responder transmit | `pm.encryption.channel.r2i.v1` |

The raw `crypto_kx` outputs and the HKDF pseudorandom key are wiped after
expand. The X25519 ephemeral secret is moved into derivation and wiped when
that `KeyPair` is destroyed. The channel stores the transcript hash as its
context. It does not store the original context string.

There is no API that imports a channel key or resets its counters. A host
that copies the key bytes out and builds another cipher is outside this
profile.

### Completion

This profile uses three messages. There is no completion acknowledgement.

| Side | `complete()` becomes true | What that does not mean |
|---|---|---|
| Initiator | `write_message` of message 3 returned success. Derivation ran before the state became `InitiatorDone`. | The responder has not necessarily read message 3. |
| Responder | `read_message` of message 3 verified the initiator signature and derivation succeeded. The state is `ResponderDone`. | The initiator has not been told. |

`take_channel` fails until `complete()` is true. After it succeeds, the
handshake no longer holds the channel. Application data is a `PME2` frame
on that channel object.

The initiator may seal after producing message 3. The responder has no
channel, and therefore cannot accept application data, until message 3
verifies. A transport that delivers a frame before message 3 has to buffer
it. The channel object will not. `chat-harness` waits until the responder
reports complete before the initiator seals. That wait is harness policy on
top of this contract, not a fourth handshake message.

Any handshake failure moves to `Failed`, wipes the local identity handle
and the ephemeral, and refuses later reads and writes.

### Frames

`PME2` version 1. XChaCha20-Poly1305. The nonce is 24 random bytes from
`randombytes_buf`. A random nonce does not replace the replay window.

| Offset | Field |
|---|---|
| 0 | `PME2` |
| 4 | version `1` |
| 5 | direction: `1` initiator to responder, `2` responder to initiator |
| 6 | content-type length, `u16`, 1 to 128 |
| 8 | sequence, `u64` |
| 16 | session id, 16 |
| 32 | nonce, 24 |
| 56 | ciphertext length, `u32`, including the 16-byte tag |
| 60 | content-type bytes |
| then | ciphertext |

The content-type bytes are an opaque label. `open` compares them to the
caller's expected label. It does not parse a media type.

Additional data is the bytes before the ciphertext, then the context length
as `u32` (always 32 on this path), then the 32-byte transcript hash. The
nonce, sequence, direction, version, session id, ciphertext length, and
content type are inside that prefix. Changing any of them changes the
additional data.

A frame is accepted only after the AEAD verifies and the replay window
accepts the sequence. Header checks run first. A wrong magic, version,
direction, session, content type, or length rejects the frame and does not
move the window. Those checks read the clear header, so a rejection is not
itself proof that the header was authentic.

The replay rule is `SequenceZeroThenWindow`, width 64. Sequence 0 is
required before any other sequence is accepted. A higher sequence before
that returns `stale` and does not move the window. After 0, a sequence more
than 63 behind the highest returns `stale`. A sequence already in the
bitmap returns `replay`. The window is consulted before decrypt, so a
modified frame whose sequence was already accepted returns `replay` rather
than `authentication_failed`. The window moves only after decrypt succeeds.
A failed decrypt does not move it.

### Channel lifetime

One established channel holds one transmit key and one receive key for the
lifetime of that object. `k_channel_ratchet` is false. A copy of either key
decrypts every frame in that direction, past and future, until the object
is destroyed. The channel does not store plaintext history.

`seal` refuses when the next sequence is `2^64-1`. The counter does not
wrap. There is no rekey and no reconnect inside `SecureChannel`. A new
session is a new handshake and a new key pair. Destroying the channel wipes
both keys. The default plaintext cap is 64 MiB. Callers may pass a smaller
cap. The chat harness uses 16 KiB.

Unauthenticated `crypto_kx`, when `PM_ENCRYPTION_UNAUTHENTICATED_KX` is
compiled, is a different constructor. It does not pin an identity and it
does not use this HKDF. This model does not describe it. The chat harness
refuses it.

## Artifact

A file is one random 32-byte content key, XChaCha20-Poly1305 per chunk, and
one `crypto_box_easy` of that key per recipient. This is not
`crypto_box_seal`. The sender's long-term file secret is the box sender.
The recipient's file public key is the box recipient. The Ed25519 identity
signs the manifest. It does not open the content key.

`name` and `media_type` are caller strings inside the signed body. They are
length-checked and stored. The cipher does not branch on them. The manifest
is signed. It is not encrypted. A holder of the offer blob can read the
name, the media-type string, the size, the hashes, and every recipient
public key.

### Nonce

The chunk nonce is 24 bytes and is injective for one transfer id:

| Bytes | Field |
|---|---|
| 0..15 | transfer id, 16 bytes, copied whole |
| 16..19 | revision, `u32` |
| 20..23 | chunk index, `u32` |

Nothing is truncated and nothing is concatenated as a variable-length
string. The same content key must not be used with the same nonce and a
different plaintext. `create_file_offer` draws a new content key, encrypts
each index once, and wipes the key before it returns. The key is not
returned to the caller. A later call, including a retry after a crash, draws
another content key. Reusing the same transfer id and revision in that new
call repeats the nonce and does not repeat the key.

`reseal_file_chunk` always returns `InvalidArgument` and writes no
ciphertext. That refusal lives in the process. There is no persisted sender
log. A host that kept the content key and called XChaCha itself could
violate the nonce rule. This API does not hand that key out.

A revision is a `u32` in the signed body and in the nonce. Zero is rejected.
The library does not decide what a new revision means. If the caller mints a
new offer, it gets a new content key, so the nonce sequence may start at
index 0 again.

### Recipient seal

Each seal is the recipient file public key, a random 24-byte box nonce, and
the box. The box plaintext is 101 bytes:

| Bytes | Field |
|---|---|
| 0 | `PMFK` |
| 4 | version `1` |
| 5 | transfer id, 16 |
| 21 | room id, 16 |
| 37 | recipient file public key, 32 |
| 69 | content key, 32 |

`crypto_box_easy` appends a 16-byte MAC, so the box is 117 bytes. Open
checks the magic, version, transfer, room, and recipient public key after
the box authenticates. The sender public key used for that open is
`manifest.sender_file`. Its role is the `crypto_box` sender identity. It is
not an anonymous ephemeral, and it is not a second copy of the Ed25519
identity.

The seal hash is BLAKE2b-256 over the seals in order. Each seal contributes
the recipient public key, the box nonce, the box length as `u16`, and the
box. That hash is inside the signed manifest body. At most 32 recipients.

### Manifest body

The signed body is:

| Field | Width |
|---|---|
| `PMFM` | 4 |
| version `1`, suite `1` | 2 |
| transfer id, room id | 16 + 16 |
| sender Ed25519, sender file X25519 | 32 + 32 |
| name length and bytes | `u16` + bytes, 1 to 128, no path separators |
| media-type length and bytes | `u16` + bytes, 1 to 64, printable ASCII |
| plaintext size | `u64` |
| chunk size | `u32`, 1 to 1 MiB |
| revision | `u32`, not zero |
| content hash | 32, BLAKE2b-256 of the whole plaintext |
| chunk count and chunk hashes | `u32` + count times 32 |
| recipient seal hash | 32, BLAKE2b-256 of the canonical seal list |

The chunk count must equal `ceil(size / chunk_size)`, or 0 when the size is
0. The count is rejected above 4096 before the hash table is allocated, and
the chunk size is rejected above 1 MiB. Each chunk hash is BLAKE2b-256 of
that chunk's plaintext. The seal hash is the last field of the signed body.
The Ed25519 signature is 64 bytes and is stored after the body. It is not
part of the body.

`create_file_offer` sorts recipient public keys and rejects a duplicate.
`FileInbox::open` rejects a seal list that is empty, larger than 32, or not
strictly increasing, and it rejects a seal hash that does not match that
list. The signature is then checked over the body, including that hash.

The offer blob is `PMFO`, version `1`, the manifest body, the signature, a
`u16` recipient count, then each seal as public key, nonce, `u16` box
length, and box. Chunk ciphertext is not inside this blob.

Chunk additional data is the domain `pm.encryption.file.chunk.v1`, the
transfer id, the room id, the revision, the index, and the plaintext length,
each integer a `u32`.

`FileInbox::accept` takes chunks in any order. A second ciphertext at an
accepted index is a replay and does not replace the plaintext. `assemble`
requires every chunk, each chunk hash, the total size, and the content hash.
A resumed snapshot is checked against the same manifest. `FileSnapshot`
wipes its copy on destruction. Other copies the caller made are the
caller's.

A later offer that omits a recipient does not make an older ciphertext
unreadable. Removal is not revocation.

### Recipient key binding

`create_file_offer` seals to the file public keys it is given. The manifest
signature then covers that list. It does not, by itself, prove that a file
public key belongs to a pinned device.

`DeviceFileKey` is a separate statement. The device's Ed25519 identity signs:

```text
pm.encryption.device-file-key.v1
format version 1
key version u32, not zero
not_before u64
not_after u64, strictly after not_before
device Ed25519 32
file public key 32
```

The carrier is `PMDK`, format version `1`, those fields, and the 64-byte
signature. It is not a field of the file manifest. `authorize_device_file_keys`
accepts a statement only when the signer is the pinned device, the key
version is the version the caller pinned, the caller-supplied time is inside
`[not_before, not_after)`, and the signature matches. A duplicate device, a
substituted file key, a different version, and a time outside the window are
rejected. `create_authorized_file_offer` runs that check and then calls
`create_file_offer`.

The window is the one in the statement. Leaving a room does not set it.
Rotation is a new statement with a new version. The caller pins the version
it accepts. The library does not keep a history of retired versions.

## Datagram

`PMD1` version 1 is one already-delimited packet. A stream has to carry an
external length before this library sees the packet. The plaintext cap is
64 KiB. XChaCha20-Poly1305. The flow id is an opaque 1 to 32 byte string
chosen by the host. It does not mean audio or video.

The key is one sender's key for one flow id, one scope, and one epoch.
`SecureEndpoint::open_flow` keeps the only send counter. `SecureFlow::accept`
installs a receiver and `seal` on that object fails. Two receivers of the
same wrap do not each start a counter at 0. A holder of the raw key bytes
can still build a cipher outside this API and forge. That is symmetric AEAD.
This profile does not add a group sender authentication on top of it.

There is no API that saves a send counter and loads it back. A restarted
process mints a new key. It does not continue the old counter.

| Field | Width |
|---|---|
| `PMD1` | 4 |
| version `1` | 1 |
| epoch | `u32` |
| sequence | `u64` |
| timestamp, caller units | `u32` |
| flow id | length byte, then 1 to 32 bytes |
| scope | length byte, then 0 to 64 bytes |
| ciphertext | plaintext plus a 16-byte tag |

The nonce is 24 bytes: epoch as `u32`, sequence as `u64`, then the first 12
bytes of an unkeyed 32-byte BLAKE2b. The hash input is one length byte, the
flow id, one length byte, and the scope. Additional data is the header
before the ciphertext. A different id, scope, or epoch is `wrong_session`
and does not move the window.

The replay rule is `AnySequenceThenWindow`, width 64, per receiver of that
sender key. The first packet may carry any sequence. A sequence already
accepted is `replay`. A sequence more than 63 behind the highest is `stale`.
Authentication runs before the window. A modified frame is
`authentication_failed` even when its sequence was already accepted. The
window moves only after both checks succeed. A failed open does not move it,
and a failed replay check clears the plaintext.

The send counter refuses `2^64-1`. `rekey` is the sender's operation. It
draws a new key at the next epoch for the same id and scope, and epoch
`2^32-1` refuses another step. The returned wrap is receive-only. A
receiver's `accept_next` requires the same id and scope and a greater epoch.
An equal or older wrap is `stale` and leaves the receiver in place. A
receiver who keeps the previous object can still open the previous epoch.
Nothing in the wrap names a room member or decides who may mint the next
epoch. The host chooses which sender it installed. `close` wipes the local
object only.

The key wrap is version `1`, epoch, id, scope, and the 32 key bytes, with
one length byte each for the id and the scope. It is a secret. The signal
text session can carry it. The broker does not need to understand it.
`pm-encryption vectors` prints the first packet, the packet after rekey, and
two packets whose labels would have collided under an unlength-prefixed
hash. Those fields are in `tests/vectors/kat.v1.json`.

## What a verifier can rely on

- A pinned Ed25519 peer is checked on message 1 and message 2. The handshake
  does not create that pin.
- Message 2 and message 3 authenticate the transcript above, including both
  identities and both ephemerals. Message 1 does not.
- Each direction of a channel has its own key, derived from the matching
  `crypto_kx` output and a distinct info string.
- An accepted `PME2` frame was authenticated under that directional key with
  the header and the transcript hash as additional data. The replay window
  then recorded its sequence.
- An accepted file chunk matches the signed chunk hash and the content hash,
  under a nonce fixed by transfer, revision, and index.
- An accepted datagram was authenticated under one sender's key for that
  flow id, scope, and epoch. The receiver object for a wrap does not seal.
- A `DeviceFileKey` accepted by `authorize_device_file_keys` was signed by
  the pinned Ed25519 device, for the pinned version, inside the statement's
  time window. `create_authorized_file_offer` seals only to those file keys.

## What this model does not claim

- Identity hiding. Both handshake identities are in the clear.
- A completion signal from the responder to the initiator.
- Intra-session key evolution on the channel. The handshake ephemeral is
  wiped after derivation, so a later compromise of the Ed25519 signing key
  does not recompute that channel. Compromise of the channel key itself
  reads that whole direction. There is no post-compromise recovery.
- Forward secrecy for a file whose content key has been opened.
- That `create_file_offer` itself checks a device binding. The file envelope
  does not carry the `DeviceFileKey` statement. The authorized function is
  the check.
- Confidentiality of file metadata.
- Revocation of ciphertext a recipient already holds.
- A ratchet, a rekey, or a restored counter on `SecureChannel`.
- That the signal text room, MLS, a listening broker, or WebRTC is this
  profile. Signal is upstream libsignal 0.108.0 behind its own option.
  `PMD1` is the datagram profile above, not a WebRTC transport.
- Linux or Android. This tree has been built on Windows.
