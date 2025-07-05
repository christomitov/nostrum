defmodule Nostrum.Voice.Event do
  @moduledoc false

  alias Nostrum.Cache.UserCache
  alias Nostrum.Constants
  alias Nostrum.Struct.VoiceWSState
  alias Nostrum.Voice
  alias Nostrum.Voice.Audio
  alias Nostrum.Voice.Crypto
  alias Nostrum.Voice.Payload
  alias Nostrum.Voice.Session

  require Logger

  @spec handle(map(), VoiceWSState.t()) :: VoiceWSState.t() | {VoiceWSState.t(), iodata()}
  def handle(payload, state) do
    state = update_sequence(state, payload)

    payload["op"]
    |> Constants.atom_from_voice_opcode()
    |> handle_event(payload, state)
  end

  defp update_sequence(state, %{"seq" => seq} = _payload), do: %{state | seq: seq}

  defp update_sequence(state, _payload), do: state

  defp handle_event(:ready, payload, state) do
    Logger.debug("VOICE READY")

    mode = Crypto.encryption_mode(state.bot_options, payload["d"]["modes"])

    voice =
      Voice.update_voice(state.voice_pid, state.guild_id,
        ssrc: payload["d"]["ssrc"],
        ip: payload["d"]["ip"],
        port: payload["d"]["port"],
        encryption_mode: mode,
        udp_socket: Audio.open_udp()
      )

    {my_ip, my_port} = Audio.discover_ip(voice.udp_socket, voice.ip, voice.port, voice.ssrc)

    {%{state | encryption_mode: mode}, Payload.select_protocol_payload(my_ip, my_port, mode)}
  end

  defp handle_event(:session_description, payload, state) do
    Logger.debug("VOICE SESSION DESCRIPTION")

    secret_key = payload["d"]["secret_key"] |> :erlang.list_to_binary()

    Voice.update_voice_async(state.voice_pid, state.guild_id,
      secret_key: secret_key,
      rtp_sequence: 0,
      rtp_timestamp: 0
    )

    Session.on_voice_ready(state.conn_pid)

    %{state | secret_key: secret_key}
  end

  defp handle_event(:heartbeat_ack, _payload, state) do
    Logger.debug("VOICE HEARTBEAT_ACK")
    %{state | last_heartbeat_ack: DateTime.utc_now(), heartbeat_ack: true}
  end

  defp handle_event(:resumed, _payload, state) do
    Logger.info("VOICE RESUMED")
    state
  end

  defp handle_event(:hello, payload, state) do
    state = %{state | heartbeat_interval: payload["d"]["heartbeat_interval"]}

    GenServer.cast(state.conn_pid, :heartbeat)

    if state.identified do
      Logger.info("RESUMING")
      {state, Payload.resume_payload(state)}
    else
      Logger.info("IDENTIFYING")
      {%{state | identified: true}, Payload.identify_payload(state)}
    end
  end

  defp handle_event(:client_connect, payload, state) do
    Logger.debug(fn ->
      user_id = payload["d"]["user_id"] |> String.to_integer()

      "Voice client connected: #{case UserCache.get(user_id) do
        {:ok, %{username: username}} -> username
        _ -> user_id
      end}"
    end)

    state
  end

  defp handle_event(:client_disconnect, payload, state) do
    Logger.debug(fn ->
      user_id = payload["d"]["user_id"] |> String.to_integer()

      "Voice client disconnected: #{case UserCache.get(user_id) do
        {:ok, %{username: username}} -> username
        _ -> user_id
      end}"
    end)

    state
  end

  defp handle_event(:codec_info, _payload, state), do: state

  defp handle_event(:speaking, payload, state) do
    ssrc = payload["d"]["ssrc"]
    user_id = payload["d"]["user_id"] |> String.to_integer()
    ssrc_map = Map.put(state.ssrc_map, ssrc, user_id)
    %{state | ssrc_map: ssrc_map}
  end

  # DAVE Protocol event handlers
  defp handle_event(:dave_protocol_prepare_transition, payload, state) do
    Logger.debug("DAVE PROTOCOL PREPARE TRANSITION: #{inspect(payload)}")
    # For now, just acknowledge the event - full DAVE implementation would go here
    state
  end

  defp handle_event(:dave_protocol_execute_transition, payload, state) do
    Logger.debug("DAVE PROTOCOL EXECUTE TRANSITION: #{inspect(payload)}")
    # For now, just acknowledge the event - full DAVE implementation would go here
    state
  end

  defp handle_event(:dave_protocol_ready_for_transition, payload, state) do
    Logger.debug("DAVE PROTOCOL READY FOR TRANSITION: #{inspect(payload)}")
    # For now, just acknowledge the event - full DAVE implementation would go here
    state
  end

  defp handle_event(:dave_protocol_prepare_epoch, payload, state) do
    Logger.debug("DAVE PROTOCOL PREPARE EPOCH: #{inspect(payload)}")
    # For now, just acknowledge the event - full DAVE implementation would go here
    state
  end

  defp handle_event(:dave_mls_external_sender_package, payload, state) do
    Logger.debug("DAVE MLS EXTERNAL SENDER PACKAGE: #{inspect(payload)}")
    # For now, just acknowledge the event - full DAVE implementation would go here
    state
  end

  defp handle_event(:dave_mls_key_package, payload, state) do
    Logger.debug("DAVE MLS KEY PACKAGE: #{inspect(payload)}")
    # For now, just acknowledge the event - full DAVE implementation would go here
    state
  end

  defp handle_event(:dave_mls_proposals, payload, state) do
    Logger.debug("DAVE MLS PROPOSALS: #{inspect(payload)}")
    # For now, just acknowledge the event - full DAVE implementation would go here
    state
  end

  defp handle_event(:dave_mls_commit_welcome, payload, state) do
    Logger.debug("DAVE MLS COMMIT WELCOME: #{inspect(payload)}")
    # For now, just acknowledge the event - full DAVE implementation would go here
    state
  end

  defp handle_event(:dave_mls_announce_commit_transition, payload, state) do
    Logger.debug("DAVE MLS ANNOUNCE COMMIT TRANSITION: #{inspect(payload)}")
    # For now, just acknowledge the event - full DAVE implementation would go here
    state
  end

  defp handle_event(:dave_mls_welcome, payload, state) do
    Logger.debug("DAVE MLS WELCOME: #{inspect(payload)}")
    # For now, just acknowledge the event - full DAVE implementation would go here
    state
  end

  defp handle_event(:dave_mls_invalid_commit_welcome, payload, state) do
    Logger.debug("DAVE MLS INVALID COMMIT WELCOME: #{inspect(payload)}")
    # For now, just acknowledge the event - full DAVE implementation would go here
    state
  end

  defp handle_event(event, _payload, state) do
    Logger.debug("UNHANDLED VOICE GATEWAY EVENT #{event}")
    state
  end
end
