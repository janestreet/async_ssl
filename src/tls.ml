open! Core
open! Async
open! Import
module Connection = Ssl.Connection

let teardown_connection ~outer_rd ~outer_wr =
  let%bind () = Writer.close ~force_close:(Clock.after (sec 30.)) outer_wr in
  Reader.close outer_rd
;;

let reader_writer_pipes ~outer_rd ~outer_wr =
  let reader_pipe_r, reader_pipe_w = Pipe.create () in
  let writer_pipe = Writer.pipe outer_wr in
  upon (Reader.transfer outer_rd reader_pipe_w) (fun () ->
    (* must close the writer before the readers, otherwise everything breaks. *)
    teardown_connection ~outer_rd ~outer_wr >>> fun () -> Pipe.close reader_pipe_w);
  upon (Pipe.closed writer_pipe) (fun () ->
    Deferred.choose
      [ Deferred.choice (Clock.after (sec 30.)) (fun () -> ())
      ; Deferred.choice
          (Pipe.downstream_flushed writer_pipe)
          (fun (_ : Pipe.Flushed_result.t) -> ())
      ]
    >>> fun () -> don't_wait_for (teardown_connection ~outer_rd ~outer_wr));
  reader_pipe_r, writer_pipe
;;

let reader_writer_of_pipes ~app_rd ~app_wr =
  let%bind inner_rd = Reader.of_pipe (Info.of_string "async_ssl_tls_reader") app_rd in
  upon (Reader.close_finished inner_rd) (fun () -> Pipe.close_read app_rd);
  let%map inner_wr, _ = Writer.of_pipe (Info.of_string "async_ssl_tls_writer") app_wr in
  Writer.set_raise_when_consumer_leaves inner_wr false;
  inner_rd, inner_wr
;;

let call_handler_and_cleanup ~outer_rd:_ ~outer_wr ~inner_rd ~inner_wr f =
  Monitor.protect f ~finally:(fun () ->
    (* Close writer before reader in-case they share the underlying FD *)
    let%bind () = Writer.close inner_wr in
    Deferred.all_unit
      [ (* Close the reader for completeness *)
        Reader.close inner_rd
        ; (* Wait for [Async_ssl] to close [outer_wr] in response to
             [inner_wr] having been closed. *)
        Writer.close_finished outer_wr
      ])
;;

let wrap_connection ~negotiate outer_rd outer_wr ~f =
  let net_to_ssl, ssl_to_net = reader_writer_pipes ~outer_rd ~outer_wr in
  let app_to_ssl, app_wr = Pipe.create () in
  let app_rd, ssl_to_app = Pipe.create () in
  match%bind negotiate ~app_to_ssl ~ssl_to_app ~net_to_ssl ~ssl_to_net with
  | Error error ->
    let%map () = teardown_connection ~outer_rd ~outer_wr in
    Error.raise error
  | Ok conn ->
    let%bind inner_rd, inner_wr = reader_writer_of_pipes ~app_rd ~app_wr in
    call_handler_and_cleanup ~outer_rd ~outer_wr ~inner_rd ~inner_wr (fun () ->
      f conn inner_rd inner_wr)
;;

let wrap_server_connection tls_settings outer_rd outer_wr ~f =
  let ca_file = Config.Server.ca_file tls_settings in
  let ca_path = Config.Server.ca_path tls_settings in
  let version = Config.Server.tls_version tls_settings in
  let options = Config.Server.tls_options tls_settings in
  let crt_file = Config.Server.crt_file tls_settings in
  let key_file = Config.Server.key_file tls_settings in
  let allowed_ciphers = Config.Server.allowed_ciphers tls_settings in
  wrap_connection
    ~negotiate:
      (Ssl.server
         ?ca_file
         ?ca_path
         ~version
         ~options
         ~crt_file
         ~key_file
         ~allowed_ciphers
         ())
    outer_rd
    outer_wr
    ~f:(fun conn r w ->
      match Ssl.Connection.peer_certificate conn with
      | None | Some (Ok (_ : Ssl.Certificate.t)) -> f conn r w
      | Some (Error error) -> Error.raise error)
;;

let listen
      ?max_connections
      ?backlog
      ?buffer_age_limit
      tls_settings
      where_to_listen
      ~on_handler_error
      ~f
  =
  Tcp.Server.create
    ?max_connections
    ?backlog
    ?buffer_age_limit
    ~on_handler_error
    where_to_listen
    (fun sock r w -> wrap_server_connection tls_settings r w ~f:(f sock))
;;

let wrap_client_connection tls_settings outer_rd outer_wr ~f =
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
  wrap_connection
    ~negotiate:
      (Ssl.client
         ?ca_file
         ?ca_path
         ?crt_file
         ?key_file
         ~verify_modes
         ~allowed_ciphers
         ~version
         ~options
         ~hostname
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

let with_connection ?interrupt tls_settings where_to_connect ~f =
  Async.Tcp.with_connection ?interrupt where_to_connect (fun socket outer_rd outer_wr ->
    wrap_client_connection tls_settings outer_rd outer_wr ~f:(f socket))
;;
