defmodule OpenTokTest do
    use ExUnit.Case
    doctest OpenTok
    
    test "Check that JWT token is generated" do
        assert OpenTok.jwt
    end

    test "Generation of OpenTok session" do
        response = OpenTok.session_create
        {:json, [session]} = response
        assert session["session_id"]
    end
end
