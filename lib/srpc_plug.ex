defmodule SrpcPlug do
  @moduledoc """
  CxTBD Documentation for SrpcPlug
  """

  import Plug.Conn

  alias :srpc_srv, as: Srpc

  ##================================================================================================
  ##
  ##  Initialize
  ##
  ##================================================================================================
  def init(%{srpc_handler: _, srpc_bypass: _} = opts) do
    opts
  end

  def init(%{srpc_handler: _} = opts) do
    opts
    |> Map.put_new(:srpc_bypass, false)
  end

  def init(_) do
    raise "SrpcPlug requires option value for :srpc_handler"
  end

  ##================================================================================================
  ##
  ##  Process request
  ##
  ##================================================================================================
  ##------------------------------------------------------------------------------------------------
  ##  Process SPRC POST to /
  ##------------------------------------------------------------------------------------------------
  def call(%{method: "POST", path_info: []} = conn, %{srpc_bypass: false,
                                                      srpc_handler: srpc_handler}) do
    conn
    |> time_stamp(:srpc_start)
    |> read_body
    |> case do
         {:ok, "", conn} ->
           conn
           |> respond({:error, "Empty body"})
         {:ok, body, conn} ->
           body
           |> Srpc.parse_packet(srpc_handler)
           |> process_srpc(srpc_handler, conn)
         _ ->
           conn
       end
  end

  ##------------------------------------------------------------------------------------------------
  ##  Decline process SPRC POST to /path
  ##------------------------------------------------------------------------------------------------
  def call(%{method: "POST"} = conn, %{srpc_bypass: false}) do
    conn
    |> respond({:error, "Invalid path: Only SRPC POST to / accepted"})
  end

  ##------------------------------------------------------------------------------------------------
  ##  Decline process SPRC request to /path
  ##------------------------------------------------------------------------------------------------
  def call(conn, %{srpc_bypass: false}) do
    conn
    |> respond({:error, "Invalid request: Only SRPC POST to / accepted"})
  end

  ##------------------------------------------------------------------------------------------------
  ##  Bypass SRPC
  ##------------------------------------------------------------------------------------------------
  def call(conn, %{srpc_bypass: true}) do
    conn
  end

  ##================================================================================================
  ##
  ##  Process SRPC packet
  ##
  ##================================================================================================
  ##------------------------------------------------------------------------------------------------
  ##  Process lib exchange
  ##------------------------------------------------------------------------------------------------
  defp process_srpc({:lib_exchange, req_data}, srpc_handler, conn) do

    req_data
    |> Srpc.lib_exchange(srpc_handler)
    |> case do
         {:ok, resp_data} ->
           conn
           |> assign(:req_type, :lib_exchange)
           |> respond({:data, resp_data})
         not_ok ->
           conn
           |> respond(not_ok)
       end
  end

  ##------------------------------------------------------------------------------------------------
  ##  Process srpc action
  ##------------------------------------------------------------------------------------------------
  defp process_srpc({:srpc_action, client_info, req_data}, srpc_handler, conn) do
    conn
    |> assign(:req_type, :srpc_action)
    |> assign(:client_info, client_info)

    case Srpc.srpc_action(client_info, req_data, srpc_handler) do
      {_srpc_action, {:invalid, _} = invalid} ->
        conn
        |> respond(invalid)
      {srpc_action, result} ->
        conn
        |> assign(:srpc_action, srpc_action)
        |> respond(result)
    end
  end

  ##------------------------------------------------------------------------------------------------
  ##  Process invalid request
  ##------------------------------------------------------------------------------------------------
  defp process_srpc({:invalid, _} = invalid, _, conn), do: conn |> respond(invalid)

  ##------------------------------------------------------------------------------------------------
  ##  Process app request
  ##------------------------------------------------------------------------------------------------
  defp process_srpc({:app_request, client_info, data}, srpc_handler, conn) do
    conn = conn
    |> assign(:req_type, :app_request)
    |> assign(:client_info, client_info)

    case Srpc.unwrap(client_info, data, srpc_handler) do
      {:ok, {nonce, << app_map_len  :: size(16),
                       app_map_data :: binary - size(app_map_len),
                       app_body     :: binary >>}} ->
        app_map_data
        |> Poison.decode
        |> case do
             {:ok, app_map} ->
               conn
               |> build_app_conn(app_map)
               |> assign(:body, app_body)
               |> assign(:nonce, nonce)
               |> assign(:srpc_proxy, app_map["proxy"] || :undefined)
               |> put_req_header("content-length", app_body |> byte_size |> Integer.to_string)
               |> register_before_send(&post_process/1)
             :error ->
               conn
               |> respond({:error, "Invalid app map in request packet"})
           end
      {:ok, _data} ->
        conn
        |> respond({:error, "Invalid data in request packet"})
      {:error, _} = error ->
        conn
        |> respond(error)
    end
  end

  ##------------------------------------------------------------------------------------------------
  ##  Build app conn
  ##------------------------------------------------------------------------------------------------
  defp build_app_conn(conn, app_map) do
    conn = conn
    |> delete_req_header("content-type")

    app_headers = for {k,v} <- Map.to_list(app_map["headers"]), do: {String.downcase(k), v}

    %Plug.Conn{
      adapter: conn.adapter,
      assigns: conn.assigns,
      host: conn.host,
      method: app_map["method"],
      owner: conn.owner,
      path_info: split_path(app_map["path"]),
      peer: conn.peer,
      port: conn.port,
      remote_ip: conn.remote_ip,
      query_string: app_map["query"] || "",
      req_headers: conn.req_headers ++ app_headers,
      request_path: app_map["path"],
      scheme: conn.scheme
    }
  end

  ##================================================================================================
  ##
  ##  Post-process
  ##
  ##================================================================================================
  defp post_process(conn) do
    case conn.assigns[:req_type] do
      :app_request -> post_process_app_request(conn)
      _ -> conn
    end
  end

  defp post_process_app_request(conn) do
    app_headers = List.foldl(conn.resp_headers, %{}, fn({k,v}, map) -> Map.put(map, k, v) end)

    nonce = case conn.assigns[:nonce] do
              :undefined -> ""
              value -> value
            end

    info_data = %{"respCode" => conn.status,
                  "headers" => app_headers,
                  "cookies" => conn.resp_cookies}
    |> Poison.encode!
    info_len = byte_size(info_data)
    packet = << info_len :: 16, info_data :: binary, conn.resp_body :: binary >>

    client_info = conn.assigns[:client_info]

    {status, srpc_body} =
      case Srpc.wrap(client_info, nonce, packet) do
        {:ok, body} ->
          {200, body}
        {:error, reason} ->
          assign(conn, :reason, reason)
          {400, reason}
      end

    %Plug.Conn{
      adapter: conn.adapter,
      assigns: conn.assigns,
      host: conn.host,
      owner: conn.owner,
      peer: conn.peer,
      port: conn.port,
      remote_ip: conn.remote_ip,
      scheme: conn.scheme,
      state: conn.state,
      status: status,
      resp_body: srpc_body
    }
  end

  ##================================================================================================
  ##
  ##  Responses
  ##
  ##================================================================================================

  # Convenience function. Some SRPC functions return successful processing as {:ok, data}.
  defp respond(conn, {:ok, data}), do: respond(conn, {:data, data})

  defp respond(conn, {:data, body}) do
    conn
    |> resp_headers(:data)
    |> put_resp_header("content-length", body |> byte_size |> Integer.to_string)
    |> time_stamp(:srpc_end)
    |> send_resp(200, body)
    |> halt
  end

  # All SRPC errors are reported as 400 Bad Request
  defp respond(conn, {:error, reason}) do
    conn
    |> assign(:reason, reason)
    |> resp_headers(:text)
    |> time_stamp(:srpc_end)
    |> send_resp(400, "Bad Request")
    |> halt
  end

  defp respond(conn, {:invalid, reason}) do
    conn
    |> assign(:reason, "Invalid Request: #{inspect reason}")
    |> assign(:app_info, :undefined)
    |> assign(:srpc_action, :invalid)
    |> resp_headers(:text)
    |> time_stamp(:srpc_end)
    |> send_resp(403, "Forbidden")
    |> halt
  end

  ##
  ## Response Headers
  ##
  defp resp_headers(conn, :data) do
    conn
    |> put_resp_content_type("application/octet-stream")
    |> resp_headers
  end

  defp resp_headers(conn, :text) do
    conn
    |> put_resp_content_type("text/plain")
    |> resp_headers
  end

  defp resp_headers(conn) do
    conn
    |> put_resp_header("x-srpc-plug", "Srpc Plug/0.1.0")
  end

  defp split_path(path) do
    for segment <- :binary.split(path, "/", [:global]), segment != "", do: segment
  end

  defp time_stamp(conn, marker) do
    conn
    |> assign(marker, :erlang.monotonic_time(:micro_seconds))
  end

end
