if Code.ensure_loaded?(Secp256k1) do
  defmodule Noise.Crypto.DH.Secp256k1 do
    @moduledoc """
    secp256k1 Diffie-Hellman, via the optional `lib_secp256k1` dependency.

    `secp256k1` is not one of the DH functions defined by the Noise
    specification. This module follows the convention established by
    Lightning's BOLT-8 (`Noise_XK_secp256k1_ChaChaPoly_SHA256`):

      * `DHLEN` is 33 — public keys are transmitted in compressed SEC1 form.
      * `DH()` returns `SHA256(compressed shared point)`, 32 bytes, which is
        libsecp256k1's default ECDH output.

    Only available when `{:lib_secp256k1, "~> 0.8"}` is in your dependencies.
    """
    @behaviour Noise.Crypto.DH

    @impl Noise.Crypto.DH
    def dhlen, do: 33

    @impl Noise.Crypto.DH
    def valid_seckey?(seckey), do: Secp256k1.valid_seckey?(seckey)

    @impl Noise.Crypto.DH
    def generate_keypair, do: Secp256k1.keypair(:compressed)

    @impl Noise.Crypto.DH
    def dh({seckey, _pubkey}, pubkey) do
      if Secp256k1.valid_pubkey?(pubkey),
        do: {:ok, Secp256k1.ecdh(seckey, pubkey)},
        else: {:error, :invalid_public_key}
    end
  end
end
