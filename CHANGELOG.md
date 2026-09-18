# Changelog

## 0.3.0

Security-hardening release with a breaking API. Every network-facing function
now returns `{:error, reason}` instead of crashing or silently misbehaving.

### Breaking

- `Noise.handshake_step/2` returns `{:complete, message, state}` on the last
  message instead of a cipher-state pair. Call `Noise.split/1` to get
  `{send, receive}` cipher states — already ordered for your role — and
  `Noise.handshake_hash/1` / `Noise.remote_static/1` for channel binding
  and peer identity.
- `Noise.encrypt/3` and `Noise.decrypt/3` return `{:ok, data, state}` or
  `{:error, reason}`; they raise `ArgumentError` on a keyless cipher state.
- `Noise.HandshakeState.initialize/4` takes a keyword list
  (`s:`, `rs:`, `e:`, `re:`, `psks:`) instead of positional arguments, and
  validates it: missing/forbidden keys, PSK count and PSK length raise
  `ArgumentError`.
- `Noise.CipherState`, `Noise.SymmetricState` and `Noise.HandshakeState`
  are opaque; `Noise.Handshake`, `Noise.Crypto` and `Noise.Utils` are removed.
- `c:Noise.Crypto.DH.dh/2` returns `{:ok, shared} | {:error, :invalid_public_key}`.
- Requires Elixir 1.18.

### Fixed

- Decryption failures no longer advance the nonce (spec §5.1), and are
  reported as `{:error, :decrypt_failed}` all the way up through the
  handshake instead of raising `CaseClauseError`/`:crypto` errors.
- The reserved nonce `2^64-1` is enforced (`{:error, :nonce_exhausted}`);
  `CipherState.set_nonce/2` rejects out-of-range values.
- The 65535-byte message limit (spec §3) is enforced on read and write.
- Truncated handshake messages and ciphertexts shorter than the tag return
  `{:error, :malformed_message}` instead of `MatchError`.
- Low-order / invalid remote public keys return
  `{:error, :invalid_public_key}` instead of raising from `:crypto`.
- `pskN` modifiers outside the pattern's message count (e.g. `NNpsk3`),
  `psk01`, and unknown modifiers (`fallback`) are rejected instead of
  silently producing a non-PSK pattern under a PSK name.
- Handshake functions enforce whose turn it is (`{:error, :wrong_turn}`).
- Private keys, PSKs, chaining keys and cipher keys are redacted from
  `inspect/1` output; previously they were hex-dumped into crash logs.
- `secp256k1` DH is now functional: it follows the Lightning BOLT-8
  convention (33-byte compressed keys, `SHA256(shared point)`) via the
  optional `lib_secp256k1` dependency, and is verified against the BOLT-8
  test vectors. Previously it emitted 65-byte keys against `DHLEN = 33`.
- Typespecs: key/hash types are byte-sized, all public functions have specs,
  Dialyzer runs in `mix check`.

### Added

- `Noise.write_message/2`, `Noise.read_message/2`, `Noise.split/1`,
  `Noise.handshake_hash/1`, `Noise.remote_static/1`.
- `Noise.HandshakeState.next_action/1`, `complete?/1`, `initiator?/1`.
- Negative and boundary tests (tag flips, truncation, nonce ceiling, message
  limit, wrong turn) and BOLT-8 vectors; GitHub Actions CI running `mix check`.

## 0.2.0

- implemented PSK support
- implemented deferred patterns support
- added "public API" in the `Noise` module
- added support for running tests from test vector files

## 0.1.0

- initial implementation
