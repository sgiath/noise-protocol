defmodule Noise.Vectors.CacophonyTest do
  use ExUnit.Case, async: true

  alias Noise.VectorRunner

  @moduletag :vectors
  @moduletag :cacophony

  @vectors_file "test/vectors/cacophony.json"
  @external_resource @vectors_file

  for vector <- VectorRunner.load_vectors_from_file(@vectors_file) do
    name = vector["name"] || vector["protocol_name"] || "unknown"

    test "cacophony: #{name}" do
      VectorRunner.run_vector(unquote(Macro.escape(vector)))
    end
  end
end
