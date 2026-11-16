# encryption.cpp

Standalone C++20 security protocol library and test CLI for PolyMech/Tanit.

**Status:** standalone transport-neutral secure channel and a chat-oriented
HTTP/SSE test harness implemented; not integrated into Tanit.  
**License:** BSD-3-Clause for this package. Vendored dependencies retain their
own licenses.

The targets will be:

```text
pm-encryption-lib    reusable library
pm-encryption        standalone CLI and protocol test driver
```

The package is intentionally below phone mesh, chat, VFS, WebRTC, Android, and
the Tanit host. It owns cryptographic protocol state and deterministic security
rules. It does not own UI, contacts, room presentation, sockets, filesystem
pickers, media, or product policy.

The design context is in `../../docs/phone-mesh.md`.

## Implemented now

`pm-encryption-lib` currently provides the transport- and payload-neutral
`pm::encryption::SecureChannel`:

- ephemeral X25519 initiator/responder session keys through libsodium
  `crypto_kx`;
- independent initiator-to-responder and responder-to-initiator keys;
- XChaCha20-Poly1305 authenticated frames (`PME2/v1`);
- session ID, direction, sequence, content type, and caller context binding;
- a 64-frame replay/reordering window;
- strict frame bounds and typed failures;
- move-only key/channel types with secret-key clearing;
- deterministic seeded identities for protocol tests.

The channel API does not contain chat, HTTP, SSE, file, or media concepts.
Those are vertical protocols which pass bounded payload bytes, a content type,
and an authenticated caller context into the channel.

The standalone `pm-encryption` CLI provides a chat vertical for exercising the
generic channel over real HTTP/SSE:

```text
pm-encryption capabilities
pm-encryption selftest
pm-encryption scenario tanit-chat-wifi
pm-encryption roundtrip --text "hello"
pm-encryption server --host 127.0.0.1 --port 0 --once
pm-encryption client --url http://127.0.0.1:<port> --text "hello"
```

The server/client harness proves encrypted JSON requests and independently
encrypted SSE events over real HTTP, including `[DONE]`. It uses a short-lived,
single-use ephemeral server challenge and does not log the prompt.

The harness intentionally reports `authenticated_peer:false`. Its ephemeral
HTTP key exchange is vulnerable to an active man-in-the-middle unless an
external trust layer authenticates the server key. Production E2EE therefore
still requires the pairing identity or pinned TLS identity to sign/bind that
challenge. The harness validates framing and streaming, not production trust.

Not implemented yet:

- durable device identity and secure key storage;
- authenticated pairing/challenge signatures;
- crash-safe persistent counters or ratchet state;
- libsignal, offline messages, and multi-device convergence;
- MLS groups;
- files or media;
- any Tanit, Android, VFS, or WebRTC integration.

## Goals

1. Provide one portable security core for Windows, Android NDK, Linux, and
   future hosts.
2. Prove authenticated online E2EE for Tanit chat over Wi-Fi before touching
   the product integration.
3. Add asynchronous one-to-one messaging through a reviewed Signal Protocol
   implementation only after the online identity and state foundations are reliable.
4. Add secure file manifests, encrypted chunks, replay protection, resume, and
   verification as a separate transport-neutral layer.
5. Add group messaging through MLS later.
6. Expose every protocol through a small C++ API and the `pm-encryption` CLI.
7. Test hostile inputs, crashes, rollback, duplicates, reordering, concurrency,
   and migrations before adding product UI.
8. Keep algorithms, persistence, transport, and host policy replaceable behind
   narrow interfaces.

## Non-goals

- Designing new cryptographic algorithms or a “Signal-like” protocol.
- Replacing TLS, WebRTC DTLS/SRTP, STUN, TURN, or an SFU.
- Owning network discovery, rendezvous, VFS paths, chat UI, or Android services.
- Passing plaintext files, audio, or video through the CLI server. The test
  server decrypts chat bodies only at its endpoint to verify the protocol.
- Hiding transport metadata such as peer addresses, timing, or byte counts.
- Treating encryption as authorization. Callers must still enforce grants,
  mounts, room membership, consent, and capture state.
- Claiming that encrypted storage protects an already compromised, unlocked
  process.

## Package boundaries

```text
phone mesh / VFS / chat / audio / video
                  |
          pm-encryption-lib
   protocol state | envelopes | files
        |                    |
 pm::commons             crypto adapters
 errors, bytes,          libsodium
 storage contracts       libsignal (optional)
 clocks, IDs             OpenMLS (later)
```

### `commons.cpp`

`encryption.cpp` uses `commons.cpp` both as a library and as the package
template:

- target and CLI conventions follow `packages/commons.cpp`;
- portable errors, byte/file helpers, IDs, clocks, and storage contracts should
  come from `pm::commons` where they already exist;
- `encryption.cpp` links `pm-commons-lib`/`pm::commons`;
- dependency direction is one-way: commons must never link encryption;
- encryption must not copy commons implementations into this tree;
- the parent adds commons before encryption, or a standalone build resolves an
  installed `pm-commons` package;
- encryption does not call `add_subdirectory` on a sibling package.

Public headers must not include Tanit `src/` headers, Android/JNI types, Win32 UI
types, Compose, settings stores, or branding. The host passes storage, clock,
randomness, and secure-key adapters explicitly.

### Host versus library

The library owns:

- canonical protocol encoding and parsing;
- limits and typed validation errors;
- key identifiers and algorithm-suite identifiers;
- device identity statements;
- handshake transcript and session state;
- anti-replay windows, sequence/generation checks, and downgrade prevention;
- file manifests, content-key wrapping, chunk encryption, and verification;
- protocol state transitions and atomic persistence requirements;
- optional adapters for reviewed message/group protocols.

The host owns:

- user consent and capability grants;
- Android Keystore and Windows CNG/DPAPI calls;
- database/filesystem implementation;
- network sockets, WebRTC, HTTPS, rendezvous, and relay selection;
- account identity, contacts, notifications, and UI;
- file selection, SAF URI permissions, mount jails, and final file placement;
- media capture and render.

## Sibling dependencies

Third-party protocol implementations stay siblings, not copied into the BSD
package:

```text
packages/
  commons.cpp/
  encryption.cpp/       BSD PolyMech API and protocol composition
  libsignal/            pinned upstream Signal source; AGPL-3.0
```

`packages/libsignal/` should remain recognizably upstream: pinned commit,
upstream license and notices, provenance file, patch list, and reproducible
update procedure. Do not edit generated or cryptographic internals casually.
Local integration patches should be small, reviewable, and replayable.

Vendoring libsignal does not relicense it. Official libsignal currently:

- exposes supported Java, Swift, and TypeScript APIs over a Rust core;
- does not offer a supported stable C++ API;
- describes external use as unsupported;
- is AGPL-3.0.

Therefore libsignal support is optional and off by default until licensing,
distribution, update, and cross-platform API decisions are complete. Keep its
code and artifacts out of the default BSD-only library. A build must clearly
report whether Signal support is absent, dynamically serviced, or linked.

Preferred isolation:

```text
pm-encryption-lib
  -> IOneToOneProtocol interface

optional libsignal adapter/service
  -> official supported API where possible
  -> owns libsignal stores and version migration
  -> returns opaque ciphertext/state results
```

Do not bind production code to undocumented libsignal internal C symbols. A
small supervised Rust process or separately licensed adapter is preferable to
making unstable internals part of the shared C++ ABI. Process isolation helps
versioning and crash recovery; it does not remove AGPL obligations.

Other expected dependencies:

| Dependency | Role | Initial status |
|---|---|---|
| libsodium | Ed25519, X25519 primitives, XChaCha20-Poly1305, secure random | Required for the first crypto profile |
| libsignal | PQXDH, Double Ratchet, multi-device session management | Optional experiment, gated |
| OpenMLS | RFC 9420 group messaging | Later optional sibling |
| libdatachannel/libwebrtc | Connectivity and media transport | Host dependency, not linked into core |
| Android Keystore / Windows CNG/DPAPI | Protect local wrapping keys | Host adapter |

Every dependency is pinned. An update requires vectors, state migration tests,
license/notices review, and cross-version interoperability tests.

## Proposed tree

```text
packages/encryption.cpp/
  CMakeLists.txt
  CMakePresets.json
  package.json
  README.md
  design.md
  include/pm/encryption/
    channel.hpp          implemented generic online secure channel
    error.hpp
    bytes.hpp
    limits.hpp
    identity.hpp
    key_store.hpp
    state_store.hpp
    envelope.hpp
    handshake.hpp
    file_manifest.hpp
    file_crypto.hpp
    one_to_one.hpp
    group.hpp
  src/
    channel.cpp          implemented generic online secure channel
    encoding/
    identity/
    handshake/
    files/
    messaging/
    storage/
  cli/
    main.cpp
    commands/
  tests/
    vectors/
    scenarios/
    fuzz/
    interop/
  fixtures/
```

Keep public types small and transport-neutral. JSON belongs at the CLI edge;
signed/authenticated protocol objects use one canonical binary encoding.

## Hard-first implementation order

We start with failure modes that are expensive to retrofit. Happy-path network
demos come later.

### Layer 0 — Invariants, limits, and deterministic model

Define before choosing a wire transport:

- canonical byte encoding and strict parser;
- protocol and crypto-suite versions;
- maximum field, message, recipient, chunk, skipped-key, and state sizes;
- stable IDs for devices, sessions, transfers, rooms, manifests, and keys;
- monotonic generations and sequence numbers;
- typed errors with no secrets in messages;
- explicit state machines with one terminal result;
- atomic storage transaction contract;
- injected clock and random source for tests;
- secret/non-secret byte types and redacted formatting.

Tests begin with malformed lengths, truncation, unknown required fields,
non-canonical encodings, integer overflow, allocation limits, duplicate IDs,
state rollback, and deterministic state-machine replay.

No cryptographic operation should accept an unbounded allocation request from a
peer. Parse and validate an envelope before allocating its declared body.

### Layer 1 — Primitive adapter and vectors

Wrap the smallest useful libsodium surface:

```text
random bytes
constant-time compare
Ed25519 sign/verify
X25519 key agreement primitive
HKDF-SHA-256
XChaCha20-Poly1305 seal/open
content hash (one fixed v1 choice)
secure zero/locked allocation where supported
```

The wrapper exposes algorithms required by a named crypto suite, not every
libsodium function. Run published vectors, generated round trips, wrong-key,
wrong-nonce, modified-AAD, modified-ciphertext, truncation, and large-input
tests.

Raw X25519 is not exposed as a complete pairing protocol. The authenticated
handshake must come from a reviewed construction and bind identity, role,
version, ephemeral keys, transcript, and context.

### Layer 2 — Device identity and secure storage boundary

Implement:

- device signing identity and fingerprint;
- signed key rotation statement;
- trust states: unknown, verifying, paired, suspended, revoked;
- opaque private-key handles for platform-backed keys;
- encrypted software-key fallback with explicit status;
- identity-change and restore detection;
- atomic state-store interface.

The library must work with an in-memory deterministic store for tests. Product
hosts supply SQLite/files and platform keystores. Private keys never enter
ordinary settings or JSON.

Hard cases:

- crash between key creation and identity commit;
- stale database restored over newer key state;
- Android reinstall/data clear;
- key unavailable while the device is locked;
- two processes opening one identity;
- rotation interrupted before peers acknowledge;
- revoked identity attempting a resumed session.

### Layer 3 — Authenticated session and envelopes

Select and integrate a reviewed authenticated handshake. Add:

- initiator/responder role binding;
- transcript hash and downgrade protection;
- independent derived keys for control, manifests, key wrapping, chunks, and
  resume tokens;
- session generation and reconnect;
- replay window and duplicate/idempotency behavior;
- re-key and close;
- strict separation between authentication and authorization.

The network is a byte courier. Tests deliver frames twice, out of order,
truncated, delayed across re-key, from an old generation, and under the wrong
device/room/transfer context.

### Layer 4 — File cryptography

This is the first product-ready feature:

- signed and encrypted manifest;
- independent random content key per file version;
- authenticated fixed-size chunks;
- deterministic missing-range resume;
- final whole-content verification;
- recipient key wrapping;
- manifest revision and source-change detection;
- safe cancellation and partial-state expiry.

The file API operates on bounded byte spans/streams. It does not know Android
content URIs, desktop paths, WebRTC channels, or final destination names.

Hard cases include:

- empty, one-byte, exact-boundary, huge, and sparse files;
- final short chunk;
- duplicate/missing/reordered/corrupt chunks;
- wrong manifest, recipient, transfer, chunk index, or generation;
- source changes during encryption;
- crash before/after chunk-state commit;
- resume on another connection;
- recipient removal and key re-wrap;
- disk full and partial writes in the host adapter;
- attacker-controlled filename/metadata;
- billions-of-chunks and integer-overflow declarations.

### Layer 5 — Pairing

Pairing composes identity and the reviewed handshake:

- short-lived single-use invite;
- QR/link payload with strict limits;
- mutual identity authentication;
- verification words/fingerprint;
- visible acceptance on both devices;
- requested versus granted capabilities;
- expiry, failed-attempt throttling, revoke, and re-pair;
- no ambient trust from LAN, tailnet, account, or device name.

Test reflection, role confusion, invite reuse, race between two joiners,
expired invite, wrong fingerprint, downgrade, intercepted rendezvous, and a
device changing keys during pairing.

### Layer 6 — Signal one-to-one messaging

Only after Layers 0–5 are stable:

1. Build the pinned sibling unchanged.
2. Run upstream libsignal tests and vectors.
3. Implement the optional `IOneToOneProtocol` adapter.
4. Add a prekey service abstraction; the encryption library does not own HTTP.
5. Persist identity/prekeys/session/skipped keys transactionally.
6. Encrypt message envelopes and file-key attachment references.
7. Add cross-version and multi-device tests.

Required scenarios:

- recipient offline before the first message;
- no one-time prekey available;
- duplicate and out-of-order messages;
- more skipped messages than policy permits;
- simultaneous session initiation;
- several devices per user;
- device added/removed while another is offline;
- identity key change and safety-number warning;
- session corruption, rollback, restore, and migration;
- sender/recipient reinstall;
- delayed message from a retired session;
- dependency update reading old persisted state.

Signal handles message sessions. Tanit still owns device authorization, room
membership, attachment transfer, relay expiry, and UI.

### Layer 7 — Group messaging

Use a reviewed MLS implementation; do not extend pairwise Signal sessions into
an improvised group protocol.

Test group creation, add/remove, concurrent proposals/commits, offline members,
old epochs, replay, fork/conflict recovery, external join, key-package expiry,
state rollback, and artifact re-key policy. Group media keys are a separate
later profile.

### Layer 8 — Service/client boundary

Add this only after the in-process APIs and deterministic tests are complete.
The first server/client is a test and isolation harness, not an Internet
service.

`pm-encryption` may expose:

```text
pm-encryption selftest
pm-encryption vectors
pm-encryption identity create|show|rotate|verify
pm-encryption pair invite|accept|confirm|revoke
pm-encryption file manifest|encrypt|verify|resume
pm-encryption scenario run <name>
pm-encryption server --listen <loopback-or-local-ipc>
pm-encryption client --connect <endpoint> <command>
pm-encryption capabilities
```

Start with stdio or authenticated local IPC. A loopback server must require an
ephemeral authentication secret, enforce request/response size limits, bind to
loopback by default, and separate clients by caller/session. Never add an open
“encrypt/decrypt arbitrary bytes with stored device key” endpoint.

The service should expose protocol operations, not raw private keys:

```text
create_identity
begin_pairing / complete_pairing
create_file_manifest
seal_file_chunk / open_file_chunk
begin_message_session / encrypt_message / decrypt_message
commit_state / close_session
```

Network demo mode can connect two CLI processes through a hostile proxy that
injects loss, duplication, reordering, corruption, delay, disconnects, and
restarts. WebRTC/HTTPS adapters remain outside this package.

## Public API direction

The exact API follows the first tests, but it should have these properties:

```cpp
namespace pm::encryption {

struct Limits;
struct DeviceId;
struct SessionId;
struct TransferId;
struct Error;

class RandomSource;
class Clock;
class StateStore;
class KeyStore;
class CryptoProvider;

class PairingSession;
class SecureChannel;
class SecureSession;
class FileSender;
class FileReceiver;
class OneToOneProtocol;

} // namespace pm::encryption
```

- No singleton key store or hidden global identity.
- No exceptions across the public ABI.
- Move-only secret/session types.
- Caller-provided limits and context.
- No plaintext or keys in `operator<<`, JSON, errors, or logs.
- Parsing returns owned validated types, never views into untrusted temporary
  input.
- Storage mutations state their required transaction boundary.
- Cancellation is explicit and leaves a defined resumable or terminal state.
- APIs distinguish verification failure, unavailable key, corrupt local state,
  stale generation, replay, unsupported version, policy denial, and I/O error.

## Persistence contract

Cryptographic state is not an ordinary cache. The `StateStore` contract needs:

- compare-and-swap revision or serializable transaction;
- atomic read-modify-write for message/session advancement;
- durable commit before reporting a send/decrypt success where key reuse could
  otherwise occur;
- monotonic rollback marker when the platform can provide one;
- schema and dependency version;
- encrypted records with context-bound associated data;
- crash-safe migration and backup rules;
- per-device/process lock behavior;
- explicit corrupt-state quarantine.

Tests use a faulting store that can fail before, during, or after each write and
can return stale revisions. This precedes SQLite integration.

## Test strategy

Testing is the product for the early layers.

### Test classes

| Class | Purpose |
|---|---|
| Unit | State transitions, limits, parser, key separation |
| Published vectors | Verify primitive/protocol compatibility |
| Golden encoding | Prevent accidental wire-format drift |
| Property | Random operation sequences preserve invariants |
| Fuzz | Parsers, manifests, frames, persisted-state decoder |
| Differential | Compare adapter behavior with upstream implementation |
| Interop | Windows/Android, old/new versions, direct/service mode |
| Fault injection | RNG/key/store/disk/network failure at every boundary |
| Adversarial network | Loss, duplicate, reorder, delay, corruption, replay |
| Process death | Kill/restart at each persistence checkpoint |
| Concurrency | Same identity/session/transfer from racing callers |
| Resource | CPU, memory, disk amplification, maximum declarations |
| Long-running | Key rotation, session aging, large transfer and soak |

### Scenario fixtures

Each scenario is a directory containing:

```text
scenario.json
peer-a initial state
peer-b initial state
network script
expected terminal states
expected public events
```

Secret values are deterministic test-only fixtures and never copied into
product defaults. A scenario must be replayable through:

1. the in-process library;
2. two CLI processes;
3. the optional service/client boundary;
4. later, Android/desktop transport adapters.

The observable terminal state must agree across all four.

### Initial scenario list

- first pair and one encrypted empty file;
- first pair and multi-chunk file;
- direct transfer interrupted and resumed;
- every chunk delivered twice and in reverse order;
- one corrupted chunk followed by a valid retry;
- old-generation replay after reconnect;
- crash at every state-store commit point;
- stale database restore;
- identity rotation during an active transfer;
- revoke before accept, during transfer, and after completion;
- simultaneous pairing attempts using one invite;
- sender and receiver clocks badly skewed;
- hostile maximum-size declarations;
- two writers race one session;
- sender version N with receiver N+1 and the reverse;
- Signal first message while recipient is offline;
- Signal simultaneous initiation and multi-device convergence;
- group member removed while offline, once MLS exists.

## CLI contract

The CLI is deterministic automation first and a debugging tool second:

- one JSON object on stdout for success or protocol failure;
- diagnostics on stderr;
- success exit `0`;
- operation/protocol failure exit `1`;
- usage failure exit `2`;
- no key, plaintext, invite secret, or decrypted payload in default output;
- `--unsafe-show-secrets` exists only in test builds, clearly marks output, and
  refuses production state directories;
- tests honor `PM_ENCRYPTION_CLI`;
- commands accept explicit state directories and caller IDs;
- `selftest` runs without network or host product state.

Example desired surface:

```text
pm-encryption capabilities
pm-encryption selftest
pm-encryption scenario run fixtures/scenarios/file-resume
pm-encryption file verify --state peer-b --manifest manifest.bin --input part.bin
```

## Build and integration target

Follow the package scaffolding used by `commons.cpp`:

```text
npm run configure
npm run build:cpp
npm test
```

From the repository root, desired aliases are:

```text
npm run build:cpp:encryption
npm run test:pm-encryption
```

The host links the static library. It does not spawn `pm-encryption`, compile
`cli/`, or depend on the test server:

```cmake
if(NOT TARGET pm-encryption-lib)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/packages/encryption.cpp
                   ${CMAKE_CURRENT_BINARY_DIR}/pm-encryption-lib
                   EXCLUDE_FROM_ALL)
endif()
target_link_libraries(${HOST_TARGET} PRIVATE pm-encryption-lib)
```

The parent must make `pm::commons` and the selected crypto provider available
before adding encryption. Optional integrations use explicit CMake options:

```text
PM_ENCRYPTION_LIBSODIUM=ON
PM_ENCRYPTION_LIBSIGNAL=OFF
PM_ENCRYPTION_OPENMLS=OFF
PM_ENCRYPTION_TEST_SERVICE=OFF
PM_ENCRYPTION_FUZZ=OFF
```

Feature definitions are private unless they affect a public type. Public API
types must not change shape merely because one optional backend is absent.

## Security review gates

No layer is called complete until:

1. Threat model and trust boundaries are written.
2. Wire and persisted formats are versioned and bounded.
3. Published vectors and negative tests pass.
4. Fault injection demonstrates no nonce/key reuse after crash or rollback.
5. Fuzzing has run on every untrusted parser.
6. Cross-version migration and interoperability pass.
7. Dependency provenance, pin, license, and update procedure are recorded.
8. Logs and errors have been checked for secret/plaintext disclosure.
9. A reviewer independent of the implementation checks protocol composition.
10. Product documentation states metadata and compromise limitations.

Before production pairing, file exchange, Signal, MLS, or media-key work, obtain
an external cryptographic review of the composed protocol and storage behavior.
A reviewed primitive does not make an unreviewed composition secure.

## First deliverable

Do not begin with a phone UI or live WebRTC demo. The first deliverable is:

```text
pm-encryption selftest
  -> canonical encoding and parser limits
  -> deterministic device identities
  -> reviewed authenticated in-memory handshake
  -> signed manifest
  -> encrypted empty/one/multi-chunk files
  -> hostile-network scenario runner
  -> crash/faulting state store
  -> resume and final verification
```

It runs as two deterministic virtual peers in one process, then as two CLI
processes through the test proxy. Once that survives the complete scenario
matrix, connect it to the existing desktop/phone pairing and VFS. Signal chat,
groups, and media keys remain independent later layers.

## References

- Phone mesh design: `../../docs/phone-mesh.md`
- Existing P2P notes: `../commons.cpp/docs/security/p2p.md`
- Commons package: `../commons.cpp/README.md`
- Signal PQXDH: https://signal.org/docs/specifications/pqxdh/
- Signal Double Ratchet: https://signal.org/docs/specifications/doubleratchet/
- Signal Sesame: https://signal.org/docs/specifications/sesame/
- Official libsignal: https://github.com/signalapp/libsignal
- MLS standard: https://www.rfc-editor.org/rfc/rfc9420
- OpenMLS: https://github.com/openmls/openmls
- libsodium: https://libsodium.org/
