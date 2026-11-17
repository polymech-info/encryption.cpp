# encryption.cpp

Standalone C++20 security protocol library and test CLI for PolyMech/Tanit.

**Status:** `live_session` is a pinned online channel with one key for the
process. `group-file` seals one content key per recipient. The dev preset
also links the libsignal text room and the datagram flow facade. The
option default for libsignal stays off. MLS stays compiled out. None of this
is production E2EE. What holds is `docs/security-assessment.md`. The target
shape is `docs/design.md`. Linux and Android are not yet built.  
**Next:** `pm-encryption chat --policy live|signal` is the pairwise text
session. The same C++ is what a desktop process and an Android host call.
The pinned `PMEH` / `PME2` channel stays, because a LAN has no Tailscale.
`pm-encryption flow` is the datagram byte API.
Lifecycle and authority stay host policy.
`chat-harness` is the loopback
pair. `room-harness` is the in-process broker. Tailscale does not replace
pairing.  
**Sibling ceiling:** the library links no sibling. The standalone CLI links
`vfs.cpp` for the file scenario and uses that package's bundled path
sanitizer, so this build does not pull in `commons.cpp`.  
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

`Identity` and `Handshake` implement the `live_session` policy. The handshake
is three messages for peers that have already pinned each other's Ed25519
identity. The wire label is `sigma-i-v1`. Identities travel in the clear, so
this is not SIGMA identity protection; SA-1 in the assessment records that.
The signatures bind version, suite, context, session id, both identities, and
both X25519 ephemerals, and HKDF-SHA256 derives one channel key in each
direction. Those keys encrypt every frame until the process exits.

`signal` is a separate session policy. The dev preset links
`packages/libsignal`, an AGPL adapter over upstream `libsignal-protocol`
0.108.0. That build runs PQXDH and the Triple Ratchet for an in-memory text
room. The option default stays off, so a host that does not opt in stays
BSD-only. Sesame, durable session storage, and the upstream libsignal test
suite are still open. That session also wraps datagram flow keys. The frame
is `PMD1/v1`. The host chooses the flow id and the scope, and the epoch is
bound into the frame. A lost packet is a gap, and a repeated sequence is a
replay. `pm::host::Device` is the test
host in this package. It captures encoded bytes, publishes them on a
loopback plane, and renders them. It does not open a microphone, run a
codec, or speak WebRTC.

`FileOffer` is the group-file envelope. The sender encrypts the bytes once
with a random content key, signs the manifest with the Ed25519 identity, and
seals that key to each recipient's separate X25519 file key. A `DeviceFileKey`
statement, outside the envelope, binds that file public key to the pinned
device. A chat message
would carry the manifest, not the file. This is not MLS: there is no group
ratchet, and dropping a recipient from a later revision does not make the
older ciphertext unreadable. `pm-encryption scenario group-file` puts the
ciphertext on a `vfs.cpp` room mount and the plaintext only in the recipient
home, after every chunk and the content hash check. Staging plaintext is
deleted after publish.

The channel API does not contain chat, HTTP, SSE, file, or media concepts.
Those are vertical protocols which pass bounded payload bytes, a content type,
and an authenticated caller context into the channel.

The standalone `pm-encryption` CLI provides a chat vertical for exercising the
generic channel over real HTTP/SSE:

```text
pm-encryption capabilities
pm-encryption policy list
pm-encryption policy live
pm-encryption policy signal
pm-encryption signal-room --text "hello"
pm-encryption media-room
pm-encryption media-host
pm-encryption flow
pm-encryption selftest
pm-encryption identity --seed <64 hex chars>
pm-encryption scenario tanit-chat-wifi
pm-encryption scenario group-file
pm-encryption vectors
pm-encryption fuzz
pm-encryption chat-harness --text "hello"
pm-encryption room-harness --text "hello"
pm-encryption roundtrip --text "hello"
pm-encryption server --host 127.0.0.1 --port 0 --once
pm-encryption client --url http://127.0.0.1:<port> --text "hello"
pm-encryption server --authenticated --identity-seed <hex> --peer-key <base64>
pm-encryption client --authenticated --identity-seed <hex> --peer-key <base64> --url ... --text "hello"
```

`chat-harness` is the desktop tool: two pinned endpoints, loopback only, a
16 KiB frame cap, and no chat bytes until both sides have finished message 3.
`server` and `client` remain the broader protocol tests, including the
unauthenticated framing mode.

The server/client harness proves encrypted JSON requests and independently
encrypted SSE events over real HTTP, including `[DONE]`. It uses a short-lived,
single-use ephemeral server challenge and does not log the prompt.

Without `--authenticated`, the harness reports `authenticated_peer:false` and
`mode:unauthenticated-kx`. That mode is a test of framing only: its ephemeral
exchange is vulnerable to an active man-in-the-middle. `--authenticated`
switches the same binary to the pinned handshake and reports
`authenticated_peer:true`. The caller supplies both the local seed and the
peer's already-pinned public key. The harness still does not store identities
or decide trust.

## Feature flags

Impacting switches are CMake options, reported by `pm-encryption capabilities`,
and the HTTP mode is also a CLI flag.

| CMake option | Default | Effect |
|---|---|---|
| `PM_ENCRYPTION_LIVE_SESSION` | `ON` | Low-level online policy: pinned handshake and one channel key. `policy live` runs its isolated suite |
| `PM_ENCRYPTION_LIBSODIUM` | `ON` | X25519, Ed25519, HKDF, and XChaCha20-Poly1305. `OFF` is rejected until another profile exists |
| `PM_ENCRYPTION_UNAUTHENTICATED_KX` | `ON` | Compiles `SecureChannel::initiator/responder`, which do not bind a device identity |
| `PM_ENCRYPTION_HTTP_HARNESS` | `ON` | Compiles the standalone HTTP/SSE harness |
| `PM_ENCRYPTION_VFS` | `ON` | Links `packages/vfs.cpp` into `scenario group-file`. The library itself does not link it |
| `PM_ENCRYPTION_LIBSIGNAL` | `OFF` | AGPL-3.0 libsignal adapter. The dev preset turns it on for the text room. Release stays off |
| `PM_ENCRYPTION_OPENMLS` | `OFF` | Group-messaging adapter. Fail-closed until `packages/openmls` is vendored |

```text
cmake -S packages/encryption.cpp -B build -DPM_ENCRYPTION_LIBSIGNAL=ON
```

`--authenticated` on `server` and `client` selects the pinned handshake. The
unauthenticated challenge route and the handshake route refuse each other's
mode, so the flag changes the trust behavior rather than only the label.

Not implemented yet:

- durable device identity and secure key storage;
- pairing, invite, and fingerprint UX that produces the pinned identity;
- crash-safe persistent counters, including the signal session store;
- Sesame multi-device convergence;
- MLS groups;
- any Tanit product UI, listening broker, P2P path, Android, or WebRTC integration.

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

`commons.cpp` is the package template and the only sibling a host may link.

- standalone `npm test` links no package under `packages/`;
- a host that embeds the library may pass an already-built `pm-commons-lib`;
- encryption does not call `add_subdirectory` on commons or any other sibling;
- vfs, audio, video, llm, and Tanit stay above this package;
- dependency direction is one-way: commons must never link encryption;
- portable errors, byte/file helpers, IDs, clocks, and storage contracts should
  come from `pm::commons` when a host actually provides them;
- encryption must not copy commons implementations into this tree.

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

The host passes a `pm::encryption::LogSink` into CLI and harness entry points.
There is no process-global logger in this package. `CommonsLog` in
`commons_log.hpp` forwards that sink to `pm::log` when the host include path
provides `logging/pm_log.hpp`. The standalone CLI uses `StderrLog` instead, and
`--log-level` selects its floor. Diagnostic lines carry modes and error codes.
Protocol JSON stays on stdout. Keys, seeds, plaintext, and frames stay out of
both.

The host owns:

- user consent and capability grants;
- Android Keystore and Windows CNG/DPAPI calls;
- database/filesystem implementation;
- network sockets, WebRTC, HTTPS, rendezvous, and relay selection;
- account identity, contacts, notifications, and UI;
- file selection, SAF URI permissions, mount jails, and final file placement;
- a production microphone, camera, codec, and WebRTC socket. The test host
  in this package (`pm-encryption media-host`) feeds encoded frames and
  renders them on a loopback plane.

## Sibling dependencies

Third-party protocol implementations stay siblings, not copied into the BSD
package:

```text
packages/
  commons.cpp/
  encryption.cpp/       BSD PolyMech API and protocol composition
  libsignal/            AGPL adapter; Cargo fetches libsignal-protocol v0.108.0
```

`packages/libsignal/` does not vendor a rewritten protocol. `PROVENANCE.md`
records the tag, and `Cargo.lock` records the resolved commit. The adapter
calls the public Rust API. A version bump changes the tag, refreshes the
lock, and re-runs `signal-room`. Do not patch the upstream tree in place.

Vendoring libsignal does not relicense it. Official libsignal currently:

- exposes supported Java, Swift, and TypeScript APIs over a Rust core;
- does not offer a supported stable C++ API;
- describes external use as unsupported;
- is AGPL-3.0.

AGPL-3.0 is an accepted license for that optional sibling. It stays out of the
default build. `-DPM_ENCRYPTION_LIBSIGNAL=ON` is the switch that opts in, and
configuration fails closed until `packages/libsignal` is actually present. A
build reports the flag through `capabilities`. Linking libsignal does not
relicense the BSD core, and it does not turn the online handshake into a
Signal session.

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
| libsignal | PQXDH and the Triple Ratchet for the text room | Optional. Dev preset on, default off. Multi-device still open |
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

The current online profile is a pinned three-message handshake. Capabilities
report the wire label `sigma-i-v1`: Ed25519 signatures over a canonical
transcript, X25519 `crypto_kx`, and HKDF-SHA256 into `SecureChannel`. The
label is older than the property; see SA-1. Signal remains Layer 6 because
its session outlives one connection and must decrypt messages while the peer
is offline.

Role binding, the transcript hash, and version refusal are in this profile.
The replay rule is sequence 0, then a 64-frame window. One channel key covers
the process, and history stays outside the channel. Still to add on this layer:

- separate derived keys for control, manifests, file-key wrapping, chunks, and
  resume tokens;
- reconnect and re-key without a new pinned handshake;
- explicit close.

The network is a byte courier. Tests deliver frames twice, out of order,
truncated, delayed across re-key, from an old generation, and under the wrong
device/room/transfer context.

### Layer 4 — File cryptography

The envelope below exists and is covered by `scenario group-file`. The content
key is sealed to a separate X25519 file key. A later revision that drops a
recipient does not make the older ciphertext unreadable. It is not
product-ready while SA-15 is open:

- signed and encrypted manifest;
- independent random content key per file version;
- authenticated fixed-size chunks;
- deterministic missing-range resume;
- final whole-content verification;
- recipient key wrapping, after a `DeviceFileKey` statement for the pinned device;
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

The dev preset runs the text slice. `pm-encryption signal-room` pairs two
Ed25519 devices in the in-process broker, carries a prekey bundle and the
ciphertext as opaque frames, and checks the upstream session: the first
message opens while the recipient was offline, the reply advances the
ratchet, a later message can arrive first, a bundle with no one-time prekey
still opens, and a replay, a flipped frame, and an outsider are rejected.
The chat bytes are not printed and are not stored in the broker. Sessions
live in the adapter process only. `pm-encryption media-room` then wraps a
datagram flow key for each host-chosen flow through that session. The broker
stores the wraps and does not store the frames. `pm-encryption flow` is the
facade a later live session calls: chat bytes, binary, and encoded frames
share `seal` / `open`. Reliable messages stay on `SecureChannel`. Durable
objects stay on the file envelope. `pm-encryption media-host` is the test
host: one device captures encoded frames, the loopback plane carries the
sealed packets, and the other device renders them.

Still open on this layer:

1. Run the upstream libsignal tests and vectors.
2. Persist identity, prekeys, sessions, and skipped keys transactionally.
3. Add a prekey service. The encryption library does not own HTTP.
4. Cover file-key attachment references on this session.
5. Add cross-version and multi-device tests.

`signal-room` already covers the first three scenarios below. The rest are open:

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

Scripts live in this package (`scripts/cmake.mjs`, `scripts/ninja.mjs`). They
do not call the repository-root script directory.

```text
npm run configure
npm run build:cpp
npm run build:cpp-fast
npm test
npm run test:core
npm run test:policy
npm run test:file
npm run test:harness
npm run test:room
npm run test:signal
npm run test:media
npm run test:host
npm run test:http
npm run test:auth
```

From the repository root, the aliases are:

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

Standalone configure fetches libsodium and the CLI-only libraries itself. A
parent that embeds the library must already have defined `pm-commons-lib` when
it wants that sibling; encryption does not fetch commons. Optional integrations
use explicit CMake options:

```text
PM_ENCRYPTION_LIBSODIUM=ON
PM_ENCRYPTION_LIVE_SESSION=ON
PM_ENCRYPTION_UNAUTHENTICATED_KX=ON
PM_ENCRYPTION_HTTP_HARNESS=ON
PM_ENCRYPTION_VFS=ON
PM_ENCRYPTION_LIBSIGNAL=OFF
PM_ENCRYPTION_OPENMLS=OFF
```

Feature definitions are private unless they affect a public type. Public API
types must not change shape merely because one optional backend is absent.

## Security review gates

`docs/security-assessment.md` is the internal reading of the code we have.
Industrial reviews start from the adversary and the written design, then the
code, then fuzzing and a second implementation, and only then a reviewer who
did not write it. We have the adversary, a code reading, and deterministic
tests. The written design is that assessment, which is not an independent
review. Gates 5, 9, and 10 are open.

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

A reviewed primitive does not make an unreviewed composition secure. The
desktop harness does not close these gates.

## Delivered

Windows standalone. The library links no sibling; the CLI links `vfs.cpp` for `group-file`:

- [x] `SecureChannel` frames, replay window, and typed failures
- [x] `live_session` policy, isolated by `pm-encryption policy live`
- [x] Ed25519 `Identity` and a pinned three-message handshake into that channel
- [x] CLI split by feature, host-passed `LogSink`, `--log-level`
- [x] HTTP/SSE harness in unauthenticated and `--authenticated` modes
- [x] CMake feature flags, including fail-closed libsignal and OpenMLS
- [x] `group-file` scenario: separate file keys, vfs room mount, hostile chunks, resume, staging wipe
- [x] Published vectors and a deterministic parser fuzz
- [x] `chat-harness`: pinned loopback desktop chat, 16 KiB cap, no broker
- [x] `pm::room` broker: fingerprint pairing, single-use invite, opaque relay
- [x] `npm test` covers core, `policy live`, the signal text room, the media room, group-file, vectors, fuzz, HTTP, and authenticated handshake

## Next

A live channel still uses one transmit key and one receive key for that
channel. That channel stays, because two devices on a LAN do not have
Tailscale. The signal text room ratchets through libsignal, in memory. The
test host captures and renders encoded frames on a loopback plane. A real
device, codec, and WebRTC socket stay outside this package. Sesame and a
durable store are open. An old file still opens after the recipient is
dropped from a later revision. The remaining production gates are an external
review of `docs/protocol-model.md`, a Linux and Android build, and any
listening, tailnet, or P2P broker. No new envelope until an existing
primitive cannot meet the requirement.

## Todos

Detail and code references are in `docs/security-assessment.md`.

Desktop harness, `pm-encryption chat-harness`:

- [x] SA-1 The harness and capabilities say `pinned-online`. The wire label stays `sigma-i-v1`
- [x] SA-4 Loopback only, both identities pinned in the process, unauthenticated route refused
- [x] SA-8 Chat is rejected until message 3 has finished on both sides
- [x] SA-9 The reported frame context is the transcript hash
- [x] SA-13 Binds loopback and caps a chat frame at 16 KiB
- [x] The result states one channel key and no broker

Before any production claim:

- [x] SA-2 The live channel states one key and keeps history out of the channel. The signal text room ratchets through libsignal
- [x] SA-3 File content keys are sealed to a separate X25519 `FileKey`
- [x] SA-6 `pm-encryption fuzz` mutates the handshake, frame, and file parsers
- [x] SA-7 The first accepted sequence is 0. A high sequence before that does not move the window
- [x] SA-10 Staging plaintext is deleted after publish, and file snapshots wipe themselves
- [x] SA-11 `reseal_file_chunk` refuses a second plaintext at the same index
- [x] SA-12 Member removal does not revoke an old file, and the scenario locks that
- [x] SA-14 `tests/vectors/kat.v1.json` is the handshake, frame, and file vector
- [ ] SA-15 External review of `docs/protocol-model.md`. The wire layouts and the handshake state machine are written. Nobody outside this codebase has checked them
- [ ] SA-16 Configure on Linux and the Android NDK. This pass was Windows only
- [ ] SA-17 A listening broker, tailnet bind, or P2P path is still a new adversary. The in-process broker is the stand-in
- [x] SA-18 A `DeviceFileKey` statement binds a file public key to the pinned Ed25519 identity, outside the file envelope
- [x] `signal` text room, behind `PM_ENCRYPTION_LIBSIGNAL` in the dev preset. In memory
- [x] Datagram flows (`PMD1`). Flow id, scope, and epoch are bound into the frame. The broker carries the key wrap, not the frames
- [x] `pm::host::Device` test host: capture, mute, grant, rekey, and render on a loopback plane
- [ ] A real microphone, camera, codec, and WebRTC transport
- [ ] Signal persistence, Sesame, and the upstream libsignal test suite
- [ ] Host embedding, with `commons.cpp` when the host image already has it

## References

- This package's security assessment: `docs/security-assessment.md`
- Protocol model for an external review: `docs/protocol-model.md`
- Room broker and Tailscale: `docs/room-broker.md`
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
