# Security assessment

**Date:** 2026-11-16  
**Scope:** `packages/encryption.cpp` as built on Windows: `live_session`, the
HTTP/SSE harness, `scenario group-file` through `packages/vfs.cpp`, and the
in-process `pm::room` broker.  
**Out of scope:** Tanit, a listening broker, tailnet, P2P, MLS, Android,
Linux, and a review of libsignal itself. The dev preset runs an in-memory
text room through the adapter. This document does not grade PQXDH, the
Triple Ratchet, Sesame, or session persistence.

The same-day pass below closed the items a test in this package can lock.
SA-15, SA-16, and SA-17 stay open. The byte model for SA-15 is
`docs/protocol-model.md`. The known answers are `tests/vectors/kat.v1.json`.

This is an internal reading of our own code. It is not an independent audit.
Trail of Bits runs a cryptographic assessment in five stages: scope and
protocol model, specification review, implementation review, adversarial
testing, then a written report and a re-test of the fixes. We have written
the adversary and read the code against it, and `npm test` is a fixed set of
cases. We have not written a separate specification, a machine-checked
argument, a fuzzer, or a report by someone who did not write the code.

The useful warning from that literature is composition. Threema and Bridgefy
used respectable primitives, and in Bridgefy's case libsignal itself, and the
application around them was still broken. libsodium being correct does not
make this handshake-plus-files-plus-VFS correct.

## Adversary

For the current tests the network is a loopback HTTP peer that can drop,
reorder, duplicate, and alter bytes. The peer identity is pinned by the
caller before the handshake. The VFS process can read every mount; mount
names are not a secrecy boundary, because `vfs.cpp` does not link
`acl.cpp`.

A later desktop harness is still this adversary: two local processes, no
relay. A broker or a P2P path is a different adversary. It can withhold,
replay, and substitute messages for a long time, and it has to be reviewed
as its own change.

## What holds

These properties match the code that `npm test` exercises. They are the
claims a desktop harness is allowed to repeat.

- The caller passes the peer Ed25519 key into `Handshake` before any message.
  Message 1 and message 2 are rejected when that key does not match the pin
  (`handshake.cpp`, `IdentityMismatch`). The handshake does not discover trust.
- The signed transcript is the domain string
  `pm.encryption.handshake.sigma-i.v1`, version, suite, context, session id,
  both identities, both X25519 ephemerals, and a role byte. A context or
  identity swap fails verification.
- Channel keys are HKDF-SHA256 of the `crypto_kx` output. The salt is a
  BLAKE2b hash of that transcript. Direction info strings differ
  (`pm.encryption.channel.i2r.v1` and `r2i.v1`).
- Frames are XChaCha20-Poly1305 with a random 24-byte nonce. The AAD covers
  the header and the channel context. A failed open does not move the replay
  window. The first accepted sequence is 0. A higher sequence before that
  does not move the window. After 0, the window is 64 frames.
- Identity secrets, ephemeral secrets, channel keys, file content keys, and
  `FileSnapshot` plaintext are wiped in their owning types. The file content
  key is sealed to a separate X25519 `FileKey`, not to the Ed25519 identity.
- A file is encrypted once. The manifest is signed. The recipient-seal hash
  is inside the signature. Each seal is a `crypto_box` that opens only for
  that member and checks transfer id, room id, and recipient. Carol, in the
  scenario, is rejected with `not_recipient`. Corrupt, replayed, and missing
  chunks are rejected. The inbox name is written after the content hash
  matches.
- Unauthenticated HTTP and the pinned handshake refuse each other's route.
- `PM_ENCRYPTION_LIBSIGNAL` and `PM_ENCRYPTION_OPENMLS` fail closed.

## Findings

Severity here means when it becomes a lie, not a CVSS score.

### SA-1 — The wire label says SIGMA-I. The messages are not SIGMA-I.

`Handshake::write_message` puts the initiator identity and ephemeral in
message 1, and the responder identity and ephemeral in message 2, all in the
clear. SIGMA-I's point is that those identities are encrypted under the
Diffie-Hellman result. We sign the transcript and we check the pin. We do
not hide the identity, and we do not give the identity-protection property
the name promises.

The authentication claim for a pre-pinned peer still stands. The name does
not. Capabilities currently report `handshake: sigma-i-v1`. A Tanit harness
that copies that string will overclaim.

**Before the desktop harness:** describe it as a pinned three-message
handshake. Keep the wire label until a versioned change. Do not implement a
private "SIGMA-like" variant as the fix.

### SA-2 — One channel key decrypts every frame in the process.

`from_authenticated_exchange` derives one transmit key and one receive key.
There is no ratchet. Anyone who copies those 32-byte keys, or the process
memory that holds them, reads the whole session, past and future, until the
process exits.

That is an acceptable description of an online test channel. It is not
Signal, and it is not a production chat transcript.

**Resolution:** the library states the limit. `k_channel_ratchet` is false,
capabilities report `history: out-of-channel`, and the selftest locks both.
There is still no ratchet on this channel. The `signal` policy is a different
session: the dev preset runs PQXDH and the Triple Ratchet through
`packages/libsignal` for text only, in memory. A stolen live-channel key
still reads that channel.

### SA-3 — The signing identity also decrypts files.

The first envelope converted the Ed25519 seed to X25519 and sealed the
content key to it. One long-term key both signed handshakes and opened every
file sealed to that device.

**Resolution:** `FileKey` is a separate X25519 key. The Ed25519 identity
signs the manifest. `crypto_box` seals the content key to the file key.
Capabilities report `file_key: separate-x25519` and
`file_key_is_identity: false`. The group-file scenario checks that the two
public keys differ. There is still no forward secrecy for a file whose
content key has been opened, and member removal still does not erase a
ciphertext the recipient already holds (SA-12).

### SA-4 — The default build still speaks unauthenticated key agreement.

`PM_ENCRYPTION_UNAUTHENTICATED_KX` defaults on. Without `--authenticated`,
the HTTP harness is a framing test with an active man-in-the-middle. The
routes refuse each other's mode, which is necessary and not sufficient: a
caller who forgets the flag gets a working channel.

**Before the desktop harness:** that process refuses to listen or connect
without a pinned local identity and a pinned peer. The unauthenticated
functions stay behind the test flag.

### SA-5 — The guarantees lived in the README narrative.

An auditor reads the threat model before the code, because missing
assumptions are where composition bugs hide. This file is the start of that
model. It has to be updated when the handshake or the file blob changes.
The README remains the operator guide and should point here instead of
restating a stronger protocol than the one we built.

### SA-6 — Parsers are tested by cases, not by a fuzzer.

Handshake messages, `PME2` frames, and `PMFO` file blobs are the bytes a
hostile peer actually sends. `npm test` covers the cases we thought of:
truncation, bad signature, wrong identity, corrupt chunk, replay. It does
not search the space. Trail of Bits' fourth stage is a harness that fuzzes
those parsers and replays malformed transcripts.

**Resolution:** `pm-encryption fuzz` mutates handshake messages, channel
frames, and file offers, then requires `read_message` on the signed
messages, `SecureChannel::open`, and `decode_file_offer` plus `FileInbox::open`
to reject them. `npm test` runs it. This is a fixed mutation pass, not a
coverage-guided fuzzer. A coverage-guided run is still worth adding before
an unsandboxed network, and it does not replace SA-15.

### SA-7 — The replay window anchors on whatever sequence arrives first.

`SecureChannel::open` treats the first authenticated frame as the high-water
mark. It does not require sequence 0. A later gap larger than 64 is permanent
loss. On ordered HTTP this is invisible, because the sender starts at 0 and
the receiver sees 0 first. A reordering or lossy path can pin the window to
a high sequence and make the earlier frames `stale`.

That is availability, not a confidentiality break: forging the frame still
requires the channel key.

**Resolution:** the first accepted sequence is 0. A higher sequence before
that is `stale` and leaves the window where it was. After 0, a gap inside
64 still opens, and a gap past 64 is `stale`. The selftest covers a high
sequence arriving first, reordering after 0, and a jump past the window.

### SA-8 — The initiator finishes before the responder does.

The initiator derives keys while writing message 3. The responder derives
keys only after that message verifies. If message 3 is lost, one side has a
channel and the other does not. There is no ack.

**For the harness:** application data starts only after both sides report
the handshake complete. Add that as a harness state, not as a silent retry
inside `Handshake`.

### SA-9 — The frame context is the transcript hash, not the caller string.

After a successful handshake, `SecureChannel::context_` is the 32-byte
BLAKE2b of the transcript, including interior zeros. The caller string is
bound because it is inside that transcript, and the hash is both the HKDF
salt and the AAD context. Callers who log or compare `context()` to the
string they passed will not see a match, and a future change that puts the
raw string into AAD as well would not be a no-op.

**For the harness:** pass a stable context, and do not treat the raw string
as the frame AAD.

### SA-10 — VFS is the jail, not the membership check.

`group-file` keeps ciphertext on the room mount and plaintext under the
recipient home. The final name is written only after the hash check.
Nothing in `vfs.cpp` stops another caller in the same process from reading
the room mount.

**Resolution:** `FileSnapshot` wipes plaintext in its destructor and after
resume copies a piece into the inbox. The scenario deletes staging files
after publish and reports `staging_deleted`. Plaintext still does not belong
on the shared mount. `acl.cpp` is still not what makes the ciphertext secret.

### SA-11 — File nonces are safe only for one content key.

The chunk nonce is transfer id, revision, and index. A second plaintext
under the same content key at the same index is nonce reuse, which breaks
XChaCha20-Poly1305.

**Resolution:** `create_file_offer` still mints a new key, encrypts each
index once, and wipes the key before returning. `reseal_file_chunk` refuses
the request and writes nothing. `FileInbox::accept` treats a different
ciphertext at an accepted index as a replay. The group-file scenario locks
both.

### SA-12 — A sealed file has no epoch.

The recipient list is fixed at 32 members. A new manifest revision is a new
offer only if the sender builds one. The previous ciphertext still opens
with the previous content key.

**Resolution:** the product surface says so. Capabilities report
`removal_revokes_ciphertext: false`. The group-file scenario drops Dave from
revision 2, Dave still holds the revision 1 plaintext, and Dave cannot open
revision 2. A leave-room button must not claim the old attachment is
unreadable.

### SA-13 — The HTTP harness will accept a 64 MiB frame.

`k_max_wire` is 64 MiB, and the pending-challenge table holds 128 entries
for 30 seconds. On loopback, for one shot, that is a test limit. A resident
desktop process with that cap is a memory exhaustion bug.

**For the harness:** bind loopback, one client, and a chat-sized frame cap.

### SA-14 — Tests check themselves.

The older suites prove our encoder and our decoder agree.

**Resolution:** `pm-encryption vectors` prints the handshake messages, the
transcript, the BLAKE2b salt, the HKDF info strings, one frame, and one file
offer from fixed seeds. `tests/vectors/kat.v1.json` is that output.
`npm test` fails if the bytes change. A second implementation can match the
file without calling this encoder.

### SA-15 — Nobody outside this codebase has reviewed the composition.

Gate 9 in the README asks for a reviewer who did not write the protocol.
This document does not satisfy that gate. `docs/protocol-model.md` is the
piece that reviewer would check: pinned keys, the transcript, the role byte,
the separate file key, and the explicit non-revocation. Verifpal or
CryptoVerif has not been run. Nobody outside this codebase has reviewed the
composition.

### SA-16 — Only Windows has been built.

Linux and the Android NDK have not configured this package. File paths in
the VFS scenario and the libsodium build are the pieces most likely to
differ. No security claim extends to those targets yet.

### SA-17 — A network broker is still a new adversary.

`pm::room::Broker` is an in-process relay with signature checks. It is the
shape Android will host. It does not listen, and a Tailscale node is not a
paired user. The details are in `docs/room-broker.md`. A broker that binds a
port, a tailnet address, or a P2P path still needs its own review.

`chat-harness` is the direct loopback pair. `room-harness` is the in-process
relay. Neither one is a listening broker. Review a bound port on its own.

## Desktop harness

`pm-encryption chat-harness` is that process. It binds loopback, pins both
identities itself, refuses `/v1/e2ee/session`, and rejects a chat frame until
the responder has reported message 3 complete. The frame cap is 16 KiB. The
result says `pinned-online`, `channel_key: one-for-process`, `broker: false`,
`files: false`, and `frame_context: transcript-hash`. The older `server` and
`client` commands are still the protocol tests, including the unauthenticated
framing mode and the 64 MiB cap. They are not the desktop harness.

## What the desktop harness is allowed to be

Standalone, on the desktop, as a test tool:

- pinned handshake only (SA-4, SA-8);
- capabilities text that says one channel key and no identity hiding
  (SA-1, SA-2);
- loopback or local IPC, with a small frame cap (SA-13);
- chat frames only, no attachments on this identity (SA-3);
- no broker (SA-17).

It is a harness for the protocol we have. It is not the production Tanit
chat, and it should not be wired into the product UI until SA-2 and SA-15
are resolved or explicitly accepted in that UI.

## Sources

- Trail of Bits, cryptography assessment stages:
  https://trailofbits.com/services/cryptography/
- Trail of Bits on Ockam, where missing written assumptions were the
  findings: https://blog.trailofbits.com/2024/03/05/cryptographic-design-review-of-ockam/
- Composition failures in deployed messengers, including applications that
  wrapped a strong protocol badly. The public writeups are the Threema
  analysis (https://breakingthe3ma.app/) and the Bridgefy analysis
  (https://martin.kleppmann.com/papers/bridgefy-pets22.pdf).
