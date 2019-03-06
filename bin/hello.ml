open Core
open Async
open Async_ssl

module Server = struct
  let main ~crt_file ~key_file ~allowed_ciphers ~port () =
    Tcp.Server.create
      ~on_handler_error:`Raise
      (Tcp.Where_to_listen.of_port port)
      (fun _address tcp_r tcp_w ->
         let _pipe_r, pipe_ssl_w = Pipe.create () in
         let pipe_ssl_r, pipe_w = Pipe.create () in
         match%bind
           Ssl.server
             ~options:[ Ssl.Opt.No_sslv2; Ssl.Opt.No_sslv3 ]
             ~allowed_ciphers
             ~crt_file
             ~key_file
             ~net_to_ssl:(Reader.pipe tcp_r)
             ~ssl_to_net:(Writer.pipe tcp_w)
             ~ssl_to_app:pipe_ssl_w
             ~app_to_ssl:pipe_ssl_r
             ()
         with
         | Error err ->
           printf !"Error: %{Sexp}\n" (Error.sexp_of_t err);
           Deferred.unit
         | Ok ssl ->
           let%bind w, `Closed_and_flushed_downstream closed_and_flushed =
             Writer.of_pipe (Info.of_string "Hello Server over SSL") pipe_w
           in
           printf "Client has connected, writing 1 line of data...\n";
           Writer.write w "Hello!\n";
           let%bind () = Writer.close w in
           let%bind () = closed_and_flushed in
           Ssl.Connection.close ssl;
           let%bind () = Ssl.Connection.closed ssl >>| Or_error.ok_exn in
           Writer.flushed tcp_w)
    >>= Tcp.Server.close_finished
  ;;

  let crt_file = Filename.dirname Sys.executable_name ^/ "do_not_use_in_production.crt"
  let key_file = Filename.dirname Sys.executable_name ^/ "do_not_use_in_production.key"

  let command =
    let open Command.Let_syntax in
    Command.async
      ~summary:"SSL test harness."
      [%map_open
        let port = flag "-port" (required int) ~doc:"PORT to listen on"
        and allowed_ciphers =
          flag "-ciphers" (optional string) ~doc:"CIPHERS ssl cipher spec"
        and crt_file =
          flag
            "-crt"
            (optional_with_default crt_file Filename.arg_type)
            ~doc:"CERTIFICATE pem file with certificate"
        and key_file =
          flag
            "-key"
            (optional_with_default key_file Filename.arg_type)
            ~doc:"KEY pem file with key"
        in
        let allowed_ciphers =
          match allowed_ciphers with
          | None -> `Secure
          | Some allowed_ciphers -> `Only (String.split ~on:':' allowed_ciphers)
        in
        fun () -> main ~crt_file ~key_file ~allowed_ciphers ~port ()]
  ;;
end

module Client = struct
  let maybe_print_sans ~print_sans ~ssl =
    if print_sans
    then
      (match Ssl.Connection.peer_certificate ssl with
       | None -> Deferred.Or_error.ok_unit
       | Some (Error _ as e) -> Deferred.return e
       | Some (Ok cert) ->
         (match Ssl.Certificate.subject_alt_names cert with
          | [] ->
            printf "subjectAltName not found\n";
            Deferred.Or_error.ok_unit
          | sans ->
            List.iter sans ~f:(printf "subjectAltName: %s\n");
            Deferred.Or_error.ok_unit))
      |> Deferred.Or_error.ok_exn
    else Deferred.unit
  ;;

  let maybe_print_peer_cert_chain ~print_chain ~ssl =
    if print_chain
    then (
      match Ssl.Connection.pem_peer_certificate_chain ssl with
      | Some chain -> printf "Certificate chain:\n%s\n" chain
      | None -> ())
  ;;

  let main ~allowed_ciphers ~print_sans ~print_chain ~host ~port () =
    let hp = Host_and_port.create ~host ~port in
    let wtc = Tcp.Where_to_connect.of_host_and_port hp in
    let%bind _socket, tcp_r, tcp_w = Tcp.connect wtc in
    let pipe_r, pipe_ssl_w = Pipe.create () in
    let pipe_ssl_r, _pipe_w = Pipe.create () in
    match%bind
      Ssl.client
        ~options:[ Ssl.Opt.No_sslv2; Ssl.Opt.No_sslv3 ]
        ~allowed_ciphers
        ~verify_modes:[ Ssl.Verify_mode.Verify_peer ]
        ~net_to_ssl:(Reader.pipe tcp_r)
        ~ssl_to_net:(Writer.pipe tcp_w)
        ~ssl_to_app:pipe_ssl_w
        ~app_to_ssl:pipe_ssl_r
        ()
    with
    | Error err ->
      printf !"Error: %{Sexp}\n" (Error.sexp_of_t err);
      Deferred.unit
    | Ok ssl ->
      let%bind r = Reader.of_pipe (Info.of_string "Hello Client over SSL") pipe_r in
      let%bind () = maybe_print_sans ~print_sans ~ssl in
      maybe_print_peer_cert_chain ~print_chain ~ssl;
      printf "Connected to server, reading one line of data...\n";
      let%bind result = Reader.read_line r in
      (match result with
       | `Ok line -> printf "%s\n" line
       | `Eof -> printf "Got EOF\n");
      let%bind () = Reader.close r in
      Ssl.Connection.close ssl;
      let%bind () = Ssl.Connection.closed ssl >>| Or_error.ok_exn in
      Writer.flushed tcp_w
  ;;

  let command =
    let open Command.Let_syntax in
    Command.async
      ~summary:"SSL test harness."
      [%map_open
        let host = anon ("HOST" %: string)
        and port = anon ("PORT" %: int)
        and allowed_ciphers =
          flag "-ciphers" (optional string) ~doc:"CIPHERS ssl cipher spec"
        and print_sans =
          flag "-print-sans" no_arg ~doc:"Print subjectAltNames of server certificate"
        and print_chain =
          flag "-print-chain" no_arg ~doc:"Print peer certificate chain in PEM format"
        in
        let allowed_ciphers =
          match allowed_ciphers with
          | None -> `Secure
          | Some allowed_ciphers -> `Only (String.split ~on:':' allowed_ciphers)
        in
        fun () -> main ~allowed_ciphers ~print_sans ~print_chain ~host ~port ()]
  ;;
end

let command =
  Command.group
    ~summary:"Test SSL client and server"
    [ "server", Server.command; "client", Client.command ]
;;

let () = Command.run command
