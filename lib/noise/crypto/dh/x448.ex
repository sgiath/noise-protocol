defmodule Noise.Crypto.DH.X448 do
  @moduledoc "X448 Diffie-Hellman (spec §12.2), via OTP `:crypto`."
  @behaviour Noise.Crypto.DH

  @impl Noise.Crypto.DH
  def dhlen, do: 56

  @impl Noise.Crypto.DH
  def valid_seckey?(seckey), do: is_binary(seckey) and byte_size(seckey) == 56

  @impl Noise.Crypto.DH
  def generate_keypair do
    {pubkey, seckey} = :crypto.generate_key(:ecdh, :x448)
    {seckey, pubkey}
  end

  @impl Noise.Crypto.DH
  def dh({seckey, _pubkey}, pubkey) do
    {:ok, :crypto.compute_key(:ecdh, pubkey, seckey, :x448)}
  rescue
    # OpenSSL rejects low-order points (all-zero output) with a badarg
    ErlangError -> {:error, :invalid_public_key}
  end
end
