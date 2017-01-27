defmodule OpenTok do
    @moduledoc """
    REST API wrapper to communicate with OpenTok signaling server.
    """

    require Logger
    use HTTPoison.Base

    @type opentok_response :: {:json, map()} | {:error, Exception.t}

    @default_algos ["HS256"]
    @endpoint "https://api.opentok.com"

    unless Application.get_env(:opentok, OpenTok) do
        raise "OpenTok is not configured"
    end

    unless Keyword.get(Application.get_env(:opentok, OpenTok), :key) do
        raise "OpenTok requires :key to be configured"
    end

    unless Keyword.get(Application.get_env(:opentok, OpenTok), :secret) do
        raise "OpenTok requires :secret to be configured"
    end


    @doc """
    Create new WebRTC session.

    We have to use `HTTPotion` in this case, because
    for some weird reason it's impossible to sent request without
    Content-Type in `hackney` which is the low-level driver for `HTTPoison`
    and it's a requirement for this specific OpenTok call.
    """
    @spec session_create() :: opentok_response
    def session_create do
        response = HTTPotion.post @endpoint <> "/session/create", [
            headers: ["X-OPENTOK-AUTH": jwt, 
            "Accept": "application/json"]
        ] 
        opentok_process_response(response)
    end


    @doc """
    Generate JWT to access OpenTok API services.
    """
    @spec jwt() :: String.t
    def jwt do
        life_length = config(:ttl, 60 * 5)
        salt = Base.encode16(:crypto.strong_rand_bytes(8))
        claims = %{
            iss: config(:key),
            ist: config(:iss, "project"),
            iat: :os.system_time(:seconds),
            exp: :os.system_time(:seconds) + life_length,
            jti: salt
        }

        {_, jwt} = nil
        |> jose_jwk
        |> JOSE.JWT.sign(jose_jws(%{}), claims)
        |> JOSE.JWS.compact
        # { :ok, jwt, full_claims } = Guardian.encode_and_sign("smth", :access, claims)
        jwt
    end


    defp process_url(url) do
        @endpoint <> url
    end

    @spec process_request_headers(map() | Keyword.t) :: [{binary, term}]
    defp process_request_headers(headers) when is_map(headers) do
        process_request_headers(Enum.into(headers, []))
    end
    defp process_request_headers(headers) do
        auth_headers = [
            {"X-OPENTOK-AUTH", jwt},
            {"Accept", "application/json"}
        ]
        auth_headers ++ headers
    end

    @spec opentok_process_response(%HTTPoison.Response{} | %HTTPotion.Response{}) :: opentok_response
    defp opentok_process_response(response) do
        case response do
            %{status_code: 200, body: body} ->
                json = Poison.decode!(body)
                {:json, json}
            _ ->
                Logger.error fn -> "OpenTok query: #{inspect(response)}" end
                {:error, OpenTok.ApiError}
        end
    end


    @doc false
    def config, do: Application.get_env(:opentok, OpenTok)
    @doc false
    def config(key, default \\ nil),
    do: config() |> Keyword.get(key, default) |> resolve_config(default)

    defp allowed_algos, do: config(:allowed_algos, @default_algos)
    
    defp resolve_config({:system, var_name}, default),
    do: System.get_env(var_name) || default
    defp resolve_config(value, _default),
    do: value

    defp jose_jws(headers) do
        Map.merge(%{"alg" => hd(allowed_algos())}, headers)
    end

    defp jose_jwk(the_secret = %JOSE.JWK{}), do: the_secret
    defp jose_jwk(the_secret) when is_binary(the_secret), do: JOSE.JWK.from_oct(the_secret)
    defp jose_jwk(the_secret) when is_map(the_secret), do: JOSE.JWK.from_map(the_secret)
    defp jose_jwk({mod, fun}),       do: jose_jwk(:erlang.apply(mod, fun, []))
    defp jose_jwk({mod, fun, args}), do: jose_jwk(:erlang.apply(mod, fun, args))
    defp jose_jwk(nil), do: jose_jwk(config(:secret) || false)
end
