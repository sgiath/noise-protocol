<p align="center">
  <img src="https://raw.githubusercontent.com/Sgiath/noise-protocol/master/docs/header.svg" width="820" alt="XX handshake sequence diagram: -> e, <- e, ee, s, es, -> s, se, then Split() into transport ciphers"/>
</p>

# Noise Protocol

[![Hex.pm](https://img.shields.io/hexpm/v/noise_protocol.svg?style=flat&color=blue)](https://hex.pm/packages/noise_protocol)
[![Docs](https://img.shields.io/badge/api-docs-green.svg?style=flat)](https://hexdocs.pm/noise_protocol)

Elixir implementation of the [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
(revision 34). Pure Elixir on top of OTP `:crypto`; no runtime dependencies.

## What is implemented

- **Patterns**: all one-way (`N`, `K`, `X`), fundamental (`NN` … `IX`) and
  deferred (`NK1`, `X1X1`, …) patterns, with `pskN` modifiers.
- **DH**: `25519`, `448`; `secp256k1` following the Lightning BOLT-8 convention
  (compressed 33-byte keys, `SHA256(shared point)`) when the optional
  [`lib_secp256k1`](https://hex.pm/packages/lib_secp256k1) dependency is present.
- **Cipher**: `AESGCM`, `ChaChaPoly`.
- **Hash**: `SHA256`, `SHA512`, `BLAKE2s`, `BLAKE2b`.
- Rekey, handshake hash for channel binding, explicit nonces for out-of-order
  transports (`Noise.CipherState.set_nonce/2`; replay protection is up to the
  receiver, see its docs).

Not implemented: `fallback` (Noise Pipes), `hfs`, SHA3.

Conformance is verified against the Snow and Cacophony test-vector suites
(1,352 vectors covering every pattern × cipher × hash) and BOLT-8.

## Installation

```elixir
def deps do
  [
    {:noise_protocol, "~> 0.3.0"},
    # only if you use Noise_*_secp256k1_* protocols:
    {:lib_secp256k1, "~> 0.8"}
  ]
end
```

This README tracks the `master` branch. Changes listed under *Unreleased* in
the [CHANGELOG](CHANGELOG.md) (such as one-way `split/1` returning `nil` for
the unused direction) are not in the published 0.3.0 release yet; see
[HexDocs](https://hexdocs.pm/noise_protocol) for the released API.

Requires Elixir 1.18+ and an OTP whose `:crypto` was built with the
primitives you select (`:crypto.supports/1` lists them).

## Usage

A Noise session has two phases: a **handshake** (a fixed number of messages
that authenticate the peers and agree on keys) followed by **transport**
(arbitrarily many encrypted messages). This library only produces and
consumes binaries; moving them between the two parties over TCP, WebSocket,
or anything else is up to you.

The walkthrough below uses `Noise_XX_25519_ChaChaPoly_BLAKE2s`: three
handshake messages, and both parties learn each other's static key during the
handshake so nothing needs to be known in advance. Both sides are shown in one
snippet for readability; in practice each half runs on its own machine.

```elixir
protocol = Noise.protocol("Noise_XX_25519_ChaChaPoly_BLAKE2s")

# Static keys are long-term identities: generate once, store the private key
# securely, and reuse the keypair across connections. They are generated here
# only for the demo. `{private, public}` tuples.
client_kp = Noise.generate_keypair(protocol)
server_kp = Noise.generate_keypair(protocol)

# The initiator (`true`) sends the first message; the responder (`false`)
# waits for it. The prologue is any bytes both sides must already agree on
# (a protocol version, for example); a mismatch makes the handshake fail.
# Use "" if you have nothing to bind.
client = Noise.handshake(protocol, true, "prologue", s: client_kp)
server = Noise.handshake(protocol, false, "prologue", s: server_kp)

# Every handshake_step/2 call either produces a message that must be sent to
# the peer, or consumes one received from the peer, strictly alternating.
# States are immutable: always continue with the state that is returned.

# Message 1 (-> e): the client produces `msg1` and sends it over the wire.
# The second argument is an optional payload delivered with the message.
# In XX the first payload is not encrypted, so keep it empty or non-secret.
{:ok, msg1, client} = Noise.handshake_step(client, "hello")
# ... client sends msg1 to server ...
{:ok, "hello", server} = Noise.handshake_step(server, msg1)

# Message 2 (<- e, ee, s, es): now it is the server's turn to send.
{:ok, msg2, server} = Noise.handshake_step(server, "")
# ... server sends msg2 to client ...
{:ok, "", client} = Noise.handshake_step(client, msg2)

# Message 3 (-> s, se): the last handshake message. Both sides return
# :complete instead of :ok, which tells you to stop calling handshake_step/2.
{:complete, msg3, client} = Noise.handshake_step(client, "")
# ... client sends msg3 to server ...
{:complete, "", server} = Noise.handshake_step(server, msg3)

# The handshake proves the peer holds the private key for the static public
# key it sent. Noise does NOT decide whether that key is one you trust:
# compare it against pinned keys, a database, TOFU, ... before proceeding.
server_pub = Noise.remote_static(client)
client_pub = Noise.remote_static(server)

# The handshake hash is identical on both sides and unique to this session;
# use it for channel binding (e.g. sign it in an application-level login).
# It is only available once the handshake is complete.
true = Noise.handshake_hash(client) == Noise.handshake_hash(server)

# Transport phase. split/1 turns the completed handshake into two cipher
# states, already ordered as {send, receive} for that state's role. The
# client's send state pairs with the server's receive state and vice versa.
{client_tx, client_rx} = Noise.split(client)
{server_tx, server_rx} = Noise.split(server)

# Each encrypt/decrypt returns an updated cipher state; keep using the
# returned one. Messages carry an implicit counter, so the receiver must
# decrypt them in the exact order they were encrypted.
{:ok, ciphertext, client_tx} = Noise.encrypt(client_tx, "secret")
# ... client sends ciphertext to server ...
{:ok, "secret", server_rx} = Noise.decrypt(server_rx, ciphertext)

# The other direction uses the other pair.
{:ok, reply, server_tx} = Noise.encrypt(server_tx, "got it")
# ... server sends reply to client ...
{:ok, "got it", client_rx} = Noise.decrypt(client_rx, reply)
```

### Framing

Noise messages are not self-delimiting. Handshake and transport messages can
each be up to 65535 bytes, and a transport ciphertext is exactly 16 bytes
longer than its plaintext. Over a stream transport such as TCP you need to
add framing yourself; a 2-byte big-endian length prefix is the usual choice:

```elixir
frame = <<byte_size(msg)::16, msg::binary>>
```

Anything larger than 65519 bytes of plaintext has to be split into several
`Noise.encrypt/2` calls, each one its own frame.

### Explicit read/write

`handshake_step/2` writes when it is your turn and reads otherwise. Use
`Noise.write_message/2` / `Noise.read_message/2` when you want that explicit;
they return `{:error, :wrong_turn}` if misused.

Patterns that need pre-shared keys take them as options:

```elixir
# IK: the initiator already knows the responder's static key
initiator = Noise.handshake("Noise_IK_25519_AESGCM_SHA256", true, "", s: kp_i, rs: server_pub)
responder = Noise.handshake("Noise_IK_25519_AESGCM_SHA256", false, "", s: kp_r)

# NNpsk0: one 32-byte pre-shared key per psk token
Noise.handshake("Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s", true, "", psks: [psk])
```

`Noise.handshake/4` raises `ArgumentError` for a missing key the pattern
needs, an `:s`/`:rs` the pattern does not use (so `remote_static/1` only ever
returns a key the handshake bound), an `:rs`/`:re` the peer transmits itself,
a malformed key, or a wrong number or size of PSKs.

### One-way patterns

`N`, `K` and `X` are a single message from initiator to recipient; the
recipient must never send (spec §7.4). `split/1` returns `nil` for the
direction that does not exist:

```elixir
protocol = Noise.protocol("Noise_N_25519_ChaChaPoly_BLAKE2s")
# The recipient's static keypair is long-term; the sender must already have
# its public key (distributed out of band, before any Noise message).
{_, recipient_pub} = recipient_kp = Noise.generate_keypair(protocol)

sender = Noise.handshake(protocol, true, "", rs: recipient_pub)
recipient = Noise.handshake(protocol, false, "", s: recipient_kp)

{:complete, msg, sender} = Noise.handshake_step(sender, "")
# ... sender sends msg to recipient ...
{:complete, "", recipient} = Noise.handshake_step(recipient, msg)

{tx, nil} = Noise.split(sender)
{nil, rx} = Noise.split(recipient)

{:ok, ciphertext, tx} = Noise.encrypt(tx, "one way")
# ... sender sends ciphertext to recipient ...
{:ok, "one way", rx} = Noise.decrypt(rx, ciphertext)
```

## Errors

Anything coming from the network is handled without raising:

| Reason                | Meaning                                                                                                                                  |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `:decrypt_failed`     | AEAD tag mismatch. During the handshake: the handshake failed. In transport: state unchanged; see below.                                 |
| `:malformed_message`  | Handshake message shorter than its tokens require; the handshake failed.                                                                 |
| `:message_too_long`   | Over the 65535-byte Noise limit (65519 bytes of transport plaintext).                                                                    |
| `:invalid_public_key` | The peer's DH key was rejected (bad encoding or low-order point); the handshake failed.                                                  |
| `:nonce_exhausted`    | 2^64-1 messages sent or received on one cipher state. `rekey/1` keeps the nonce, so start a new handshake.                               |
| `:wrong_turn`         | `write_message/2` on the peer's turn or vice versa.                                                                                      |
| `:handshake_complete` | Handshake function called after the last message; call `split/1`.                                                                       |

A failed handshake is final (spec §5.3): discard the handshake state and start
over instead of retrying with it.

A transport `:decrypt_failed` leaves the receive state unchanged, so a message
injected by an attacker can be dropped and the session continues. A genuine
message that was corrupted or lost cannot be recovered that way: the sender
has already used its nonce, so every later message fails as well. On a
reliable stream with implicit nonces, treat `:decrypt_failed` as fatal and
close the connection.

Private keys, PSKs and chaining keys are redacted from `inspect/1`.

## Custom primitives

DH, cipher and hash functions are behaviours (`Noise.Crypto.DH`,
`Noise.Crypto.Cipher`, `Noise.Crypto.Hash`). To use your own implementation,
build a `Noise.Protocol` struct with it; the `Noise.Protocol` docs list the
invariants (exact protocol name, `dhlen`/`hashlen`) you have to keep.

## Development

```sh
mix check   # format, compile --warnings-as-errors, credo, docs, tests
```

The spec this implementation follows is checked in as `protocol.md`.
