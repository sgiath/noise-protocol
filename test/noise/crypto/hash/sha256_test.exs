defmodule NoiseTest.Crypto.Hash.Sha256 do
  use ExUnit.Case, async: true

  alias Noise.Crypto.Hash.Sha256

  defp hex(h), do: Base.decode16!(h, case: :lower)

  test "hashlen is 32" do
    assert Sha256.hashlen() == 32
  end

  test "hash known answers, SHA-256 (FIPS 180-4)" do
    assert Sha256.hash("") ==
             hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    assert Sha256.hash("abc") ==
             hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  end

  # RFC 4231 test cases 2 and 6
  test "hmac_hash known answers" do
    assert Sha256.hmac_hash("Jefe", "what do ya want for nothing?") ==
             hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

    # a key longer than the block size is hashed first
    assert Sha256.hmac_hash(
             :binary.copy(<<0xAA>>, 131),
             "Test Using Larger Than Block-Size Key - Hash Key First"
           ) ==
             hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
  end

  # HKDF(ck, ikm, n) as defined in spec §4.3, computed independently with
  # Python's hmac + hashlib
  test "hkdf known answers for 2 and 3 outputs (spec §4.3)" do
    ck = for i <- 0..31, into: <<>>, do: <<i>>
    ikm = for i <- 0xA0..0xBF, into: <<>>, do: <<i>>

    output1 = hex("948a229701ebf4d5dba497e0dd00ff0acf4fa837d9923a437a78caec3e31cad7")
    output2 = hex("fb00e78b3295879e70686c64c4d76a6d94360abadecefb1f666f77b3edf5c348")
    output3 = hex("2dff48acd0b5519b789941832bc27f13defb289e2c3941cfa64dc6b0bcd8d56f")

    assert Sha256.hkdf(ck, ikm, 2) == {output1, output2}
    assert Sha256.hkdf(ck, ikm, 3) == {output1, output2, output3}
  end

  test "hkdf with a zero chaining key matches RFC 5869 HKDF (test case 3)" do
    # Noise's HKDF is RFC 5869 HKDF with salt = ck and empty info
    {output1, output2} = Sha256.hkdf(<<0::256>>, :binary.copy(<<0x0B>>, 22), 2)

    assert binary_part(output1 <> output2, 0, 42) ==
             hex(
               "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
             )
  end
end
