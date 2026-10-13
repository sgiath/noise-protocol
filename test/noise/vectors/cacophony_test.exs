vectors_file = "test/vectors/cacophony.json"

# ExUnit runs the tests of one module serially, so the 944 vectors are split
# into one async module per DH and cipher function to run in parallel.
groups =
  vectors_file
  |> Noise.VectorRunner.load_vectors_from_file()
  |> Enum.group_by(fn vector ->
    ["Noise", _pattern, dh, cipher, _hash] = String.split(vector["protocol_name"], "_")
    {dh, cipher}
  end)

for {{dh, cipher}, vectors} <- groups do
  defmodule Module.concat([Noise.Vectors.CacophonyTest, "DH#{dh}", cipher]) do
    use ExUnit.Case, async: true

    @moduletag :vectors
    @moduletag :cacophony

    @external_resource vectors_file

    for vector <- vectors do
      test "cacophony: #{vector["name"] || vector["protocol_name"]}" do
        Noise.VectorRunner.run_vector(unquote(Macro.escape(vector)))
      end
    end
  end
end
