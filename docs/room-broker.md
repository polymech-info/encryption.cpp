# Room broker

**Date:** 2026-11-16

`pm::room` is the in-process stand-in for the room process that will run on
Android. It lives in this package so the protocol can be tested before it has
a package of its own. The move is a directory move: `include/pm/room/` and
`src/room/` become `packages/room.cpp`, and that package links
`pm-encryption-lib`. The namespace stays `pm::room`, matching `pm::encryption`
and `pm::vfs`.

The root `CMakeLists.txt` does not add this library. Desktop `tanit.exe` and
`tanit-cli` are not wired to it. Android is not wired to it. A later host
calls the same C++ functions through a thin JNI or CLI wrapper. Kotlin does
not grow a second pairing or room parser.

## What a host does

1. Pairing is the key setup. One device signs an offer. The broker stores it
   and hands it to the other device. That device signs an accept. Both devices
   show a fingerprint over the pairing id and the two public keys, sorted.
   Pairing finishes only when the displayed fingerprints match. The first
   grant is chat. Files, audio, and video are separate grants and this broker
   rejects them.
2. The owner creates a room and signs an invite. The invite is single-use.
   Joining proves the invitee holds the matching secret.
3. Members post opaque frames. The broker checks the sender is a member and
   that the frame signature matches. It assigns the next sequence. It does
   not decrypt.
4. A chat frame may name a file manifest. The file bytes stay in the file
   path. Voice and video stay in the desktop and phone media stacks
   (`ChatWebPanel` already has those on Windows). The broker does not carry
   PCM or encoded video.

`pm-encryption room-harness` runs that sequence with two paired devices and
one outsider. `pm-encryption chat-harness` remains the direct loopback socket
test.

## Tailscale

Tailscale is WireGuard between nodes that a tailnet admin has approved. It
authenticates a node on that tailnet. It does not authenticate a Tanit user,
and it does not replace the pairing fingerprint.

What it does change:

- A stranger on a cafe LAN cannot rewrite a WireGuard packet between two
  tailnet nodes. That is the underlay. Pairing does not have to defend
  against that hop when the devices really are using Tailscale to reach each
  other.

What it does not change:

- Every other node already on the tailnet can open a TCP connection to a
  broker that listens on the tailnet address. That peer is inside the
  network, in the same way a hostile device on a home LAN is inside the
  network. They can relay, delay, and substitute bytes.
- Tailscale HTTPS or MagicDNS names the node, not the Ed25519 device key.
  Accepting "it is on my tailnet" as a substitute for the fingerprint is a
  man-in-the-middle by an authorized node.
- Binding the broker to `0.0.0.0`, or to the tailnet IP, without the pairing
  check exposes the room to every device an admin can add.

The harness therefore stays on an in-process loopback relay and reports
`tailnet: false`. A later Android or desktop host may dial a saved tailnet
address as one connectivity candidate, after pairing, and still verify the
device key. Adding that dial is a new review of the broker's bind address.
It is not a change to the fingerprint.

## tanit-cli and the desktop panel

Both would join as hosts of this API: create or load an identity, pair, join
a room, post a frame, fetch frames. `tanit-cli` has no subcommand for that
yet. `ChatWebPanel` keeps its current voice, video, and file exchange. Those
are not routed through `pm::room` until a host chooses to send their
manifest ids as room frames.
