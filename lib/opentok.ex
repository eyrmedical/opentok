defmodule OpenTok do
  @moduledoc """
  REST API wrapper to communicate with OpenTok signaling server.
  """

  require Logger
  use HTTPoison.Base

  @type opentok_response :: {:json, map()} | {:error, Exception.t()}

  @default_algos ["HS256"]
  @endpoint "https://api.opentok.com"

  @role_publisher "publisher"

  @token_prefix "T1=="

  unless Application.get_env(:opentok, OpenTok) do
    raise "OpenTok is not configured"
  end

  unless Keyword.get(Application.get_env(:opentok, OpenTok), :key) do
    raise "OpenTok requires :key to be configured"
  end

  unless Keyword.get(Application.get_env(:opentok, OpenTok), :secret) do
    raise "OpenTok requires :secret to be configured"
  end

  @spec session_create() :: opentok_response
  def session_create do
    response =
      HTTPoison.post(
        @endpoint <> "/session/create",
        "",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-OPENTOK-AUTH": jwt(),
        Accept: "application/json"
      )

    opentok_process_response(response)
  end

  @doc """
  Generate unique token to access session.
  """
  @spec generate_token(String.t(), Keyword.t()) :: String.t()
  def generate_token(session_id, opts \\ []) do
    role = Keyword.get(opts, :role, @role_publisher)
    expire_time = Keyword.get(opts, :expire_time)
    connection_data = Keyword.get(opts, :connection_data)

    ts = :os.system_time(:seconds)

    nonce =
      :crypto.strong_rand_bytes(16)
      |> Base.encode16()

    data_string =
      "session_id=#{session_id}&create_time=#{ts}&role=#{role}&nonce=#{nonce}"
      |> data_string(expire_time, connection_data)

    signature = sign_string(data_string, config(:secret))

    @token_prefix <> Base.encode64("partner_id=#{config(:key)}&sig=#{signature}:#{data_string}")
  end

  @doc """
  Generate JWT to access OpenTok API services.
  """
  @spec jwt() :: String.t()
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

    {_, jwt} =
      nil
      |> jose_jwk
      |> JOSE.JWT.sign(jose_jws(%{}), claims)
      |> JOSE.JWS.compact()

    # { :ok, jwt, full_claims } = Guardian.encode_and_sign("smth", :access, claims)
    jwt
  end

  def process_url(url) do
    @endpoint <> url
  end

  @spec process_request_headers(map() | Keyword.t()) :: [{binary, term}]
  def process_request_headers(headers) when is_map(headers) do
    process_request_headers(Enum.into(headers, []))
  end

  def process_request_headers(headers) do
    auth_headers = [
      {"X-OPENTOK-AUTH", jwt()},
      {"Accept", "application/json"}
    ]

    auth_headers ++ headers
  end

  @spec opentok_process_response(%HTTPoison.Response{}) :: opentok_response
  defp opentok_process_response(response) do
    case response do
      {:ok, %{status_code: 200, body: body}} ->
        json = Poison.decode!(body)
        {:json, json}

      _ ->
        Logger.error(fn -> "OpenTok query: #{inspect(response)}" end)
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
  defp jose_jwk({mod, fun}), do: jose_jwk(:erlang.apply(mod, fun, []))
  defp jose_jwk({mod, fun, args}), do: jose_jwk(:erlang.apply(mod, fun, args))
  defp jose_jwk(nil), do: jose_jwk(config(:secret) || false)

  @spec data_string(String.t(), nil | String.t(), nil | String.t()) :: String.t()
  defp data_string(string, nil, nil) do
    string
  end

  defp data_string(string, expire_time, nil) do
    string <> "&expire_time=#{expire_time}"
  end

  defp data_string(string, nil, connection_data) do
    string <> "&connection_data=#{URI.encode(connection_data)}"
  end

  defp data_string(string, expire_time, connection_data) do
    string
    |> data_string(expire_time, nil)
    |> data_string(nil, connection_data)
  end

  @spec sign_string(String.t(), String.t()) :: String.t()
  defp sign_string(string, secret) do
    :crypto.mac(:hmac, :sha, secret, string)
    |> Base.encode16()
  end
end
