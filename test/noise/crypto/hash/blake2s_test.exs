defmodule NoiseTest.Crypto.Hash.Blake2s do
  use ExUnit.Case, async: true

  alias Noise.Crypto.Hash.Blake2s

  defp hex(h), do: Base.decode16!(h, case: :lower)

  test "hashlen is 32" do
    assert Blake2s.hashlen() == 32
  end

  test "hash known answers, BLAKE2s-256 (RFC 7693)" do
    assert Blake2s.hash("") ==
             hex("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")

    assert Blake2s.hash("abc") ==
             hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
  end

  # computed with Python's hmac + hashlib
  test "hmac_hash known answers" do
    assert Blake2s.hmac_hash("Jefe", "what do ya want for nothing?") ==
             hex("90b6281e2f3038c9056af0b4a7e763cae6fe5d9eb4386a0ec95237890c104ff0")

    # a key longer than the block size is hashed first
    assert Blake2s.hmac_hash(
             :binary.copy(<<0xAA>>, 131),
             "Test Using Larger Than Block-Size Key - Hash Key First"
           ) ==
             hex("d23d79394f53d536a096e6514447eeaabb05ded01be32c1937da6a8f7103bc4e")
  end

  # HKDF(ck, ikm, n) as defined in spec §4.3, computed independently with
  # Python's hmac + hashlib
  test "hkdf known answers for 2 and 3 outputs (spec §4.3)" do
    ck = for i <- 0..31, into: <<>>, do: <<i>>
    ikm = for i <- 0xA0..0xBF, into: <<>>, do: <<i>>

    output1 = hex("9d01113b74478ba15419224ba266980acc1510807a277a10187e0fd4b26f022a")
    output2 = hex("60bb1d2c4422248ac29b056edfd1e200431aab15b1a0a608ead5b7681a27f538")
    output3 = hex("a4ac0f828df6dcde75e17f7a3e2c114c2680678aead098ab9fbf3352775a82df")

    assert Blake2s.hkdf(ck, ikm, 2) == {output1, output2}
    assert Blake2s.hkdf(ck, ikm, 3) == {output1, output2, output3}
  end
end
