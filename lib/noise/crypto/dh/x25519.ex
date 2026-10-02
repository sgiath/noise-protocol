defmodule Noise.Crypto.DH.X25519 do
  @moduledoc "X25519 Diffie-Hellman (spec §12.1), via OTP `:crypto`."
  @behaviour Noise.Crypto.DH

  @impl Noise.Crypto.DH
  def dhlen, do: 32

  @impl Noise.Crypto.DH
  def valid_seckey?(seckey), do: is_binary(seckey) and byte_size(seckey) == 32

  @impl Noise.Crypto.DH
  def generate_keypair do
    {pubkey, seckey} = :crypto.generate_key(:ecdh, :x25519)
    {seckey, pubkey}
  end

  @impl Noise.Crypto.DH
  def dh({seckey, _pubkey}, pubkey) do
    {:ok, :crypto.compute_key(:ecdh, pubkey, seckey, :x25519)}
  rescue
    # OpenSSL rejects low-order points (all-zero output) with a badarg
    ErlangError -> {:error, :invalid_public_key}
  end
end
