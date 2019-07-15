open Core
open Async

let handler ~body:_ _socket _request =
  let%bind r =
    Deferred.Or_error.try_with (fun () ->
      let resp_body = Cohttp_async_lib.Body.of_string "test" in
      printf !"accepted\n%!";
      return @@ `Response (Cohttp.Response.make ~status:`OK (), resp_body))
  in
  match r with
  | Ok r -> return r
  | Error _ ->
    let resp_body = Cohttp_async_lib.Body.of_string "failed" in
    return @@ `Response (Cohttp.Response.make ~status:`OK (), resp_body)
;;

let run () =
  let ssl_transport_mode =
    `OpenSSL_with_trust_chain
      ( `OpenSSL
          ( `Allowed_ciphers `Secure
          , `Crt_file_path "snakeoil.crt"
          , `Key_file_path "snakeoil.key" )
      , `Ca_file "snakeoil_ca.pem" )
  in
  let on_error _sock _exn = printf !"Error happend%!" in
  let%bind _server =
    Cohttp_async_lib.Server.create_expert
      ~on_handler_error:(`Call on_error)
      ~mode:ssl_transport_mode
      (Tcp.Where_to_listen.of_port 4567)
      (handler :> Cohttp.Http_handler.Raw.t)
  in
  printf !"listening\n%!";
  Deferred.never ()
;;

let cmd = Command.async ~summary:"Test" (Command.Param.return (fun () -> run ()))
let () = Async_command.run cmd
