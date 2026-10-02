defmodule Noise.VectorRunner do
  @moduledoc false
  # Runs one Snow/Cacophony-format test vector through the public `Noise` API,
  # checking exact ciphertexts, peer decryption, handshake hash and transport
  # messages in both directions.

  import ExUnit.Assertions

  def load_vectors_from_file(path) do
    path
    |> File.read!()
    |> JSON.decode!()
    |> Map.get("vectors")
  end

  def run_vector(vector) do
    protocol = Noise.protocol(vector["protocol_name"])
    prologue = decode_hex(vector["init_prologue"] || "")

    init = Noise.handshake(protocol, true, prologue, side_opts(vector, "init", protocol))
    resp = Noise.handshake(protocol, false, prologue, side_opts(vector, "resp", protocol))

    one_way? = Noise.Pattern.one_way?(protocol.pattern)

    run_messages(vector["messages"], {:handshake, init}, {:handshake, resp}, one_way?, vector)
  end

  defp side_opts(vector, side, protocol) do
    [
      s: decode_keypair(vector["#{side}_static"], protocol),
      e: decode_keypair(vector["#{side}_ephemeral"], protocol),
      rs: decode_hex(vector["#{side}_remote_static"]),
      psks: vector |> Map.get("#{side}_psks", []) |> Enum.map(&decode_hex/1)
    ]
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
  end

  defp run_messages([], _sender, _receiver, _one_way?, _vector), do: :ok

  defp run_messages([msg | rest], sender, receiver, one_way?, vector) do
    payload = decode_hex(msg["payload"])
    expected = decode_hex(msg["ciphertext"])

    {ciphertext, sender} = write(sender, payload, vector)
    assert ciphertext == expected, "ciphertext mismatch, expected #{msg["ciphertext"]}"

    {decrypted, receiver} = read(receiver, ciphertext, vector)
    assert decrypted == payload, "payload mismatch"

    # One-way patterns: the initiator keeps sending. Otherwise alternate.
    if one_way?,
      do: run_messages(rest, sender, receiver, one_way?, vector),
      else: run_messages(rest, receiver, sender, one_way?, vector)
  end

  defp write({:handshake, state}, payload, vector) do
    case Noise.handshake_step(state, payload) do
      {:ok, message, state} -> {message, {:handshake, state}}
      {:complete, message, state} -> {message, finish(state, vector)}
    end
  end

  defp write({:transport, tx, rx}, payload, _vector) do
    {:ok, ciphertext, tx} = Noise.encrypt(tx, payload)
    {ciphertext, {:transport, tx, rx}}
  end

  defp read({:handshake, state}, message, vector) do
    case Noise.handshake_step(state, message) do
      {:ok, payload, state} -> {payload, {:handshake, state}}
      {:complete, payload, state} -> {payload, finish(state, vector)}
    end
  end

  defp read({:transport, tx, rx}, ciphertext, _vector) do
    {:ok, payload, rx} = Noise.decrypt(rx, ciphertext)
    {payload, {:transport, tx, rx}}
  end

  defp finish(state, vector) do
    if hash = vector["handshake_hash"] do
      assert Base.encode16(Noise.handshake_hash(state), case: :lower) == hash
    end

    {tx, rx} = Noise.split(state)
    {:transport, tx, rx}
  end

  defp decode_hex(nil), do: nil
  defp decode_hex(hex), do: Base.decode16!(hex, case: :mixed)

  defp decode_keypair(nil, _protocol), do: nil

  defp decode_keypair(hex, %Noise.Protocol{dh: dh}) do
    priv = decode_hex(hex)
    {priv, derive_public_key(dh, priv)}
  end

  defp derive_public_key(Noise.Crypto.DH.X25519, priv),
    do: :crypto.compute_key(:ecdh, <<9, 0::248>>, priv, :x25519)

  defp derive_public_key(Noise.Crypto.DH.X448, priv),
    do: :crypto.compute_key(:ecdh, <<5, 0::440>>, priv, :x448)

  defp derive_public_key(Noise.Crypto.DH.Secp256k1, priv),
    do: Secp256k1.pubkey(priv, :compressed)
end
