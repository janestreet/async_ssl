open! Core
open! Async
open! Import
module Connection = Ssl.Connection
open Require_explicit_time_source

let teardown_connection ~outer_rd ~outer_wr ~time_source =
  let force_close = Time_source.after time_source (Time_ns.Span.of_sec 30.) in
  let%bind () = Writer.close ~force_close outer_wr in
  Reader.close outer_rd
;;

(* One needs to be careful around Async Readers and Writers that share the same underyling
   file descriptor, which is something that happens when they're used for sockets.

   Closing the Reader before the Writer will cause the Writer to throw and complain about
   its underlying file descriptor being closed. This is why instead of using Reader.pipe
   directly below, we write out an equivalent version which will first close the Writer
   before closing the Reader once the input pipe is fully consumed.

   Additionally, [Writer.pipe] will not close the writer if the pipe is closed, so in
   order to avoid leaking file descriptors, we allow the pipe 30 seconds to flush before
   closing the writer. *)
let reader_writer_pipes ~outer_rd ~outer_wr ~time_source =
  let reader_pipe_r, reader_pipe_w = Pipe.create () in
  let writer_pipe = Writer.pipe outer_wr in
  upon (Reader.transfer outer_rd reader_pipe_w) (fun () ->
    (* must close the writer before the readers, otherwise everything breaks. *)
    teardown_connection ~outer_rd ~outer_wr ~time_source
    >>> fun () -> Pipe.close reader_pipe_w);
  upon (Pipe.closed writer_pipe) (fun () ->
    Deferred.choose
      [ Deferred.choice
          (Time_source.after time_source (Time_ns.Span.of_sec 30.))
          (fun () -> ())
      ; Deferred.choice
          (Pipe.downstream_flushed writer_pipe)
          (fun (_ : Pipe.Flushed_result.t) -> ())
      ]
    >>> fun () -> don't_wait_for (teardown_connection ~outer_rd ~outer_wr ~time_source));
  reader_pipe_r, writer_pipe
;;

(* [Reader.of_pipe] will not close the pipe when the returned [Reader] is closed, so we
   manually do that ourselves.

   [Writer.of_pipe] will create a writer that will raise once the pipe is closed, so we
   set [raise_when_consumer_leaves] to false. *)
let reader_writer_of_pipes ~app_rd ~app_wr =
  let%bind inner_rd = Reader.of_pipe (Info.of_string "async_ssl_tls_reader") app_rd in
  upon (Reader.close_finished inner_rd) (fun () -> Pipe.close_read app_rd);
  let%map inner_wr, _ = Writer.of_pipe (Info.of_string "async_ssl_tls_writer") app_wr in
  Writer.set_raise_when_consumer_leaves inner_wr false;
  inner_rd, inner_wr
;;

let call_handler_and_cleanup ~outer_rd:_ ~outer_wr ~inner_rd ~inner_wr f =
  Monitor.protect f ~run:`Now ~rest:`Log ~finally:(fun () ->
    (* Wait for writes to flush (or fail) before attempting to close writer. Without this,
       when flushing takes longer than 5 seconds, the writer is force-closed and
       application data is truncated.

       Adding this wait is preferable to setting [Writer.close ~force_close] to ensure we
       never leak file descriptors.
    *)
    let%bind () = Writer.flushed_or_failed_unit inner_wr in
    (* Close writer before reader in-case they share the underlying FD *)
    let%bind () = Writer.close inner_wr in
    Deferred.all_unit
      [ (* Close the reader for completeness *)
        Reader.close inner_rd
      ; (* Wait for [Async_ssl] to close [outer_wr] in response to [inner_wr] having been
           closed. *)
        Writer.close_finished outer_wr
      ])
;;

let wrap_connection
  ?(timeout = Time_ns.Span.of_sec 30.)
  outer_rd
  outer_wr
  ~negotiate
  ~f
  ~time_source
  =
  let net_to_ssl, ssl_to_net = reader_writer_pipes ~outer_rd ~outer_wr ~time_source in
  let app_to_ssl, app_wr = Pipe.create () in
  let app_rd, ssl_to_app = Pipe.create () in
  let%bind negotiate =
    match%map
      Time_source.with_timeout
        time_source
        timeout
        (negotiate ~app_to_ssl ~ssl_to_app ~net_to_ssl ~ssl_to_net)
    with
    | `Timeout -> error_s [%message "Timeout exceeded"]
    | `Result connection -> connection
  in
  match negotiate with
  | Error error ->
    let%map () = teardown_connection ~outer_rd ~outer_wr ~time_source in
    Error.raise error
  | Ok conn ->
    let%bind inner_rd, inner_wr = reader_writer_of_pipes ~app_rd ~app_wr in
    call_handler_and_cleanup ~outer_rd ~outer_wr ~inner_rd ~inner_wr (fun () ->
      f conn inner_rd inner_wr)
;;

let wrap_server_connection tls_settings outer_rd outer_wr ~f ~time_source =
  let ca_file = Config.Server.ca_file tls_settings in
  let ca_path = Config.Server.ca_path tls_settings in
  let verify_modes = Config.Server.verify_modes tls_settings in
  let version = Config.Server.tls_version tls_settings in
  let options = Config.Server.tls_options tls_settings in
  let crt_file = Config.Server.crt_file tls_settings in
  let key_file = Config.Server.key_file tls_settings in
  let allowed_ciphers = Config.Server.allowed_ciphers tls_settings in
  let override_security_level = Config.Server.override_security_level tls_settings in
  wrap_connection
    outer_rd
    outer_wr
    ~negotiate:
      (Ssl.server
         ?ca_file
         ?ca_path
         ?verify_modes
         ?override_security_level
         ~version
         ~options
         ~crt_file
         ~key_file
         ~allowed_ciphers
         ())
    ~f:(fun conn r w ->
      match Ssl.Connection.peer_certificate conn with
      | None | Some (Ok (_ : Ssl.Certificate.t)) -> f conn r w
      | Some (Error error) -> Error.raise error)
    ~time_source
;;

let listen
  ?max_connections
  ?backlog
  ?buffer_age_limit
  ?advance_clock_before_tls_negotiation
  ?socket
  tls_settings
  where_to_listen
  ~on_handler_error
  ~f
  =
  Tcp.Server.create
    ?max_connections
    ?backlog
    ?buffer_age_limit
    ?socket
    ~on_handler_error
    where_to_listen
    (fun sock r w ->
       let%bind time_source =
         match advance_clock_before_tls_negotiation with
         | None -> return (Time_source.wall_clock ())
         | Some (time_source, delay) ->
           let%map () = Time_source.advance_by_alarms_by time_source delay in
           Time_source.read_only time_source
       in
       wrap_server_connection tls_settings r w ~f:(f sock) ~time_source)
;;

let wrap_client_connection ?timeout tls_settings outer_rd outer_wr ~f =
  let ca_file = Config.Client.ca_file tls_settings in
  let ca_path = Config.Client.ca_path tls_settings in
  let version = Config.Client.tls_version tls_settings in
  let options = Config.Client.tls_options tls_settings in
  let crt_file = Config.Client.crt_file tls_settings in
  let key_file = Config.Client.key_file tls_settings in
  let hostname = Config.Client.remote_hostname tls_settings in
  let allowed_ciphers = Config.Client.allowed_ciphers tls_settings in
  let verify_modes = Config.Client.verify_modes tls_settings in
  let verify_callback = Config.Client.verify_callback tls_settings in
  let session = Config.Client.session tls_settings in
  let connection_name = Config.Client.connection_name tls_settings in
  let override_security_level = Config.Client.override_security_level tls_settings in
  wrap_connection
    ?timeout
    ~negotiate:
      (Ssl.client
         ?ca_file
         ?ca_path
         ?crt_file
         ?key_file
         ?hostname
         ?session
         ?name:connection_name
         ?override_security_level
         ~verify_modes
         ~allowed_ciphers
         ~version
         ~options
         ())
    outer_rd
    outer_wr
    ~f:(fun conn inner_rd inner_wr ->
      match%bind verify_callback conn with
      | Error connection_verification_error ->
        raise_s
          [%message
            "Connection verification failed." (connection_verification_error : Error.t)]
      | Ok () -> f conn inner_rd inner_wr)
;;

let with_connection ?interrupt ?timeout tls_settings where_to_connect ~f ~time_source =
  let start_time = Time_source.now time_source in
  Async.Tcp.with_connection
    ?interrupt
    ?timeout:(Option.map timeout ~f:Time_ns.Span.to_span_float_round_nearest)
    where_to_connect
    (fun socket outer_rd outer_wr ->
       let timeout =
         Option.map timeout ~f:(fun timeout ->
           let tcp_time_elapsed = Time_ns.diff (Time_source.now time_source) start_time in
           Time_ns.Span.(timeout - tcp_time_elapsed))
       in
       wrap_client_connection
         ?timeout
         tls_settings
         outer_rd
         outer_wr
         ~f:(f socket)
         ~time_source)
;;

module For_testing = struct
  let listen = listen
  let with_connection = with_connection
end

let time_source = Time_source.wall_clock ()
let listen = listen ?advance_clock_before_tls_negotiation:None
let wrap_server_connection = wrap_server_connection ~time_source
let with_connection = with_connection ~time_source
let wrap_client_connection = wrap_client_connection ~time_source

module Expert = struct
  let connect ?interrupt ?timeout tls_settings where_to_connect =
    let conn_ivar = Ivar.create () in
    (* This will raise if the connection fails to establish which will bubble out to the
       enclosing monitor and avoid issues with the [Ivar] not getting filled. *)
    don't_wait_for
      (with_connection
         ?interrupt
         ?timeout
         tls_settings
         where_to_connect
         ~f:(fun sock conn r w ->
           Ivar.fill_exn conn_ivar (sock, conn, r, w);
           Deferred.any [ Reader.close_finished r; Writer.close_finished w ]));
    Ivar.read conn_ivar
  ;;

  let wrap_client_connection_and_stay_open tls_settings outer_rd outer_wr ~f =
    let result = Ivar.create () in
    let finished =
      wrap_client_connection tls_settings outer_rd outer_wr ~f:(fun conn r w ->
        let%bind res, `Do_not_close_until finished = f conn r w in
        Ivar.fill_exn result res;
        finished)
    in
    let%map result = Ivar.read result in
    result, `Connection_closed finished
  ;;
end
