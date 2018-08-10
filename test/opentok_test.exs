defmodule OpenTokTest do
  use ExUnit.Case
  doctest OpenTok

  @test_session_id "1_MX4xMjM0NTY3OH4-VGh1IEZlYiAyNyAwNDozODozMSBQU1QgMjAxNH4wLjI0NDgyMjI"

  test "Check that JWT token is generated" do
    assert OpenTok.jwt()
  end

  test "Generation of OpenTok session" do
    response = OpenTok.session_create()
    {:json, [session]} = response
    assert session["session_id"]
  end

  test "Generation of token" do
    token = OpenTok.generate_token(@test_session_id)
    assert token
  end
end
