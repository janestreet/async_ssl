open Core
open Async
open Async_ssl

let main ~crt_file ~key_file ~allowed_ciphers ~port () =
  Tcp.Server.create
    (Tcp.on_port port)
    (fun _address tcp_r tcp_w ->
       let _pipe_r, pipe_ssl_w = Pipe.create () in
       let pipe_ssl_r, pipe_w = Pipe.create () in
       Ssl.server
         ~options:[Ssl.Opt.No_sslv2;Ssl.Opt.No_sslv3]
         ~allowed_ciphers
         ~crt_file
         ~key_file
         ~net_to_ssl:(Reader.pipe tcp_r)
         ~ssl_to_net:(Writer.pipe tcp_w)
         ~ssl_to_app:pipe_ssl_w
         ~app_to_ssl:pipe_ssl_r
         ()
       >>= function
       | Error err ->
         printf !"Error: %{Sexp}\n" (Error.sexp_of_t err);
         Deferred.unit
       | Ok ssl ->
         Writer.of_pipe (Info.of_string "Hello over SSL") pipe_w
         >>= fun (w, `Closed_and_flushed_downstream closed_and_flushed) ->
         Writer.write w "Hello!\n";
         Writer.close w
         >>= fun () ->
         closed_and_flushed
         >>= fun () ->
         Ssl.Connection.close ssl;
         Ssl.Connection.closed ssl
         >>| Or_error.ok_exn
         >>= fun () -> Writer.flushed tcp_w
    )
  >>= Tcp.Server.close_finished
;;

let crt_file = Filename.dirname Sys.executable_name ^/ "do_not_use_in_production.crt"
let key_file = Filename.dirname Sys.executable_name ^/ "do_not_use_in_production.key"

let command =
  let open Command.Let_syntax in
  Command.async' ~summary:"SSL test harness."
    [%map_open
      let port = flag "-port" (required int) ~doc:"PORT to listen on"
      and allowed_ciphers = flag "-ciphers" (optional string) ~doc:"CIPHERS ssl cipher spec"
      and crt_file = flag "-crt" (optional_with_default crt_file file) ~doc:"CERTIFICATE pem file"
      and key_file = flag "-key" (optional_with_default key_file file) ~doc:"KEY pem file"
      in
      let allowed_ciphers = match allowed_ciphers with
        | None -> `Secure
        | Some allowed_ciphers -> `Only (String.split ~on:':' allowed_ciphers)
      in
      fun () -> main ~crt_file ~key_file ~allowed_ciphers ~port ()
    ]
;;

let () = Command.run command
