defmodule Noise.Vectors.SnowExtendedTest do
  use ExUnit.Case, async: true
  alias Noise.VectorRunner

  @vectors_file "test/vectors/snow-extended.json"
  @external_resource @vectors_file

  # P256 and XChaChaPoly are not implemented; every vector in this file uses them.
  @moduletag :skip
  @moduletag :vectors
  @moduletag :snow_extended

  for vector <- VectorRunner.load_vectors_from_file(@vectors_file) do
    name = vector["name"] || vector["protocol_name"] || "unknown"

    @tag :vectors
    test "snow-extended: #{name}" do
      VectorRunner.run_vector(unquote(Macro.escape(vector)))
    end
  end
end
