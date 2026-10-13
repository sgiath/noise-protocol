# Agent guide

## Test layers

The library is pure apart from key generation (`generate_keypair`, and
`HandshakeState` generating the ephemeral when `:e` is not given). Each layer
builds on the one below and is tested at its own interface; a layer's tests run
the layers below it for real. Nothing is mocked.

| Layer | Code | What it owns | Tests |
| --- | --- | --- | --- |
| Primitives | `lib/noise/crypto/**` | DH, AEAD and hash wrappers over `:crypto` and `lib_secp256k1` | `test/noise/crypto/**`: known answers from RFCs, FIPS and BOLT-8 |
| Descriptors | `lib/noise/pattern.ex`, `lib/noise/protocol.ex` | Name grammar, pattern table, `pskN` modifiers, primitive selection | `test/noise/pattern_test.exs`, `test/noise/protocol_test.exs` |
| State machines | `lib/noise/cipher_state.ex`, `lib/noise/symmetric_state.ex`, `lib/noise/handshake_state.ex` | Nonces and rekey; `h`/`ck` derivation and split; tokens, turns, wire parsing, key validation and handshake errors | `test/noise/cipher_state_test.exs`, `test/noise/symmetric_state_test.exs`, `test/noise/handshake_state_test.exs`, `test/noise/hostile_input_test.exs` |
| Facade | `lib/noise.ex` | `handshake_step` dispatch, `:complete` tagging, role-aware and one-way `split`, transport length bound, missing-key errors | `test/noise_test.exs` and its doctest |
| Golden | — | Byte-exact interop with other implementations, through the facade | `test/noise/vectors/*` via `test/support/vector_runner.ex`, fixtures in `test/vectors/` |

## Where a new test goes

Put a test at the lowest layer that can express the behaviour:

- A wrong primitive output: a known-answer test in `test/noise/crypto/**`.
- A pattern or protocol name parsed wrongly: `pattern_test` or `protocol_test`.
- Nonce, rekey or `h`/`ck`/split values: `cipher_state_test` or
  `symmetric_state_test`, with expected values from an independent source.
- A handshake message mis-parsed, accepted when it should fail, or failing
  with the wrong error: `hostile_input_test` for hostile wire input,
  `handshake_state_test` for initialization and turn rules.
- Only behaviour `lib/noise.ex` adds belongs in `noise_test`. If a bug can
  only be reproduced through the facade or the vectors, the layer that owns
  it lacks an interface for it; fix that rather than adding a facade test.
- A new external vector set: a new module under `test/noise/vectors/`. Split
  large sets into several async modules, since ExUnit runs one module's
  tests serially.

Run `mix test --exclude vectors` for a fast loop without the JSON vector sets.
