open Core.Std
open Async.Std
open Import

module Version = Version

module Connection = struct
  type t =
    { ssl              : Ffi.Ssl.t
    ; client_or_server : [ `Client | `Server ]
    (* The reader and writer binary IO interfaces used by SSL to exchange data without
       going through a file descriptor.  Strangely enough, to use SSL we _read from_ wbio
       and _write to_ wbio.  The names are from the perspective of the SSL library. *)
    ; rbio             : Ffi.Bio.t
    ; wbio             : Ffi.Bio.t
    (* Reads and writes to/from C must go through a bigstring.  We share it in the record
       to prevent needless reallocations. *)
    ; bstr             : bigstring
    ; name             : string
    ; app_to_ssl       : string Pipe.Reader.t
    ; ssl_to_app       : string Pipe.Writer.t
    ; net_to_ssl       : string Pipe.Reader.t
    ; ssl_to_net       : string Pipe.Writer.t
    }
  with sexp_of

  let create_exn ctx version client_or_server name
        ~app_to_ssl ~ssl_to_app ~net_to_ssl ~ssl_to_net =
    (* SSL is transferred in 16 kB packets.  Therefore, it makes sense for our buffers to
       be the same size. *)
    let ssl  = Ffi.Ssl.create_exn ctx in
    Ffi.Ssl.set_method ssl version;
    let rbio = Ffi.Bio.create () in
    let wbio = Ffi.Bio.create () in
    let default_buffer_size = 16 * 1024 in
    let bstr = Bigstring.create default_buffer_size in
    Ffi.Ssl.set_bio ssl ~input:rbio ~output:wbio;
    { ssl; client_or_server; rbio; wbio; bstr; name
    ; app_to_ssl; ssl_to_app; net_to_ssl; ssl_to_net
    }
  ;;

  let create_client_exn ?name:(nm="(anonymous)") ctx version
        ~app_to_ssl ~ssl_to_app ~net_to_ssl ~ssl_to_net =
    create_exn ctx version `Client nm ~app_to_ssl ~ssl_to_app ~net_to_ssl ~ssl_to_net
  ;;

  let create_server_exn ?name:(nm="(anonymous)") ctx version ~crt_file ~key_file
        ~app_to_ssl ~ssl_to_app ~net_to_ssl ~ssl_to_net =
    let connection =
      create_exn ctx version `Server nm ~app_to_ssl ~ssl_to_app ~net_to_ssl ~ssl_to_net
    in
    let try_both_formats ~load ~on_fail =
      load `PEM
      >>= function
      | Ok () -> return ()
      | Error _ ->
        load `ASN1
        >>| function
        | Ok () -> ()
        | Error _ -> on_fail ()
    in
    try_both_formats
      ~load:(fun file_type ->
        Ffi.Ssl.use_certificate_file connection.ssl ~crt:crt_file ~file_type)
      ~on_fail:(fun () -> failwithf "Could not load certificate file @ %s" crt_file ())
    >>= fun () ->
    try_both_formats
      ~load:(fun file_type ->
        Ffi.Ssl.use_private_key_file connection.ssl ~key:key_file ~file_type)
      ~on_fail:(fun () -> failwithf "Could not load private key file @ %s" key_file ())
    >>= fun () ->
    return connection
  ;;

  let raise_with_ssl_errors () =
    failwiths "Ssl_error" (Ffi.get_error_stack ()) <:sexp_of< string list >>
  ;;

  let blen t = Bigstring.length t.bstr

  let bptr t = Ctypes.bigarray_start Ctypes.array1 t.bstr

  (* Called when something goes horribly wrong. This makes sure that
     resources don't leak when exceptional circumstances hit. *)
  let crash_and_burn t =
    if verbose then Debug.amf _here_ "%s: crash_and_burn" t.name;
    Pipe.close_read t.app_to_ssl;
    Pipe.close      t.ssl_to_app;
    Pipe.close_read t.net_to_ssl;
    Pipe.close      t.ssl_to_net;
  ;;

  (* Write any pending data to ssl_to_net.  If you bind to the returned [unit Deferred.t],
     you wait until the write has completed all the way through the pipe to the end.

     This drains wbio whether or not ssl_to_net is closed or not.  When ssl_to_net IS
     closed, we make sure to close its matching partner: app_to_ssl. *)
  let rec write_pending_to_net t =
    if verbose then Debug.amf _here_ "%s: write_pending_to_net" t.name;
    let amount_read = Ffi.Bio.read t.wbio ~buf:(bptr t) ~len:(blen t) in
    if verbose then Debug.amf _here_ "%s:   amount_read: %i" t.name amount_read;
    if amount_read < 0
    then begin
      if verbose then Debug.amf _here_ "%s: write_pending_to_net complete" t.name;
      return ()
    end else if amount_read = 0
    then write_pending_to_net t
    else begin
      let to_write = Bigstring.to_string ~len:amount_read t.bstr in
      begin
        if not (Pipe.is_closed t.ssl_to_net)
        then begin
          if verbose then Debug.amf _here_ "%s: ssl_to_net <- '%s'" t.name to_write;
          Pipe.write t.ssl_to_net to_write
        end
        else begin
          if verbose then Debug.amf _here_ "%s: closing app_to_ssl" t.name;
          Pipe.close_read t.app_to_ssl;
          return ();
        end
      end
      >>= fun () ->
      write_pending_to_net t
    end
  ;;

  let flush t =
    if verbose then Debug.amf _here_ "%s: Flushing..." t.name;
    write_pending_to_net t
    >>= fun () ->
    Pipe.upstream_flushed t.ssl_to_net
    >>= fun _ ->
    if verbose then Debug.amf _here_ "%s: Done flush." t.name;
    return ()
  ;;

  (* Runs an ssl function (either ssl_read or ssl_write), possibly retrying the call if
     an error was returned. *)
  let rec in_retry_wrapper
    : type a. t -> f:(unit -> (a, _) Result.t) -> (a, _) Result.t Deferred.t =
    fun t ~f ->
      let ret = f () in
      let module E = Ffi.Ssl_error in
      match ret with
      | Ok x -> return (Ok x)
      | Error e ->
        if verbose then Debug.amf _here_ "%s: %s" t.name (E.sexp_of_t e |> Sexp.to_string);
        match e with
        | E.Want_read ->
          (* [Un]intuitively enough, if SSL wants a read, we need to write out all
             pending data first. *)
          flush t
          >>= fun () ->
          (* Then, write the chunk of data from the net into the rbio and try again. *)
          Pipe.read t.net_to_ssl
          >>= begin function
          | `Ok was_read ->
            Ffi.Bio.write t.rbio ~buf:was_read ~len:(String.length was_read)
            |> ignore; (* Should never fail. It's an 'infinite' buffer. *)
            in_retry_wrapper t ~f
          (* If the connection to the net died, we have to stop. Return an error,
             and close its matching pipe. *)
          | `Eof ->
            if verbose then Debug.amf _here_ "%s: closing ssl_to_app" t.name;
            Pipe.close t.ssl_to_app;
            return (Error `Stream_eof)
          end
        | E.Want_write ->
          (* If SSL requests a write, write and try again. *)
          flush t
          >>= fun () ->
          in_retry_wrapper t ~f
        (* If the underlying SSL connection died, we get an error of 'ZeroReturn'. *)
        | E.Zero_return ->
          return (Error `Session_closed)
        (* And of course, sometimes SSL is just broken. *)
        | E.Ssl_error
        | E.Want_connect
        | E.Want_accept
        | E.Want_X509_lookup
        | E.Syscall_error ->
          raise_with_ssl_errors ()
  ;;

  let do_ssl_read t =
    if verbose then Debug.amf _here_ "%s: BEGIN do_ssl_read" t.name;
    let read_as_str = ref "" in
    in_retry_wrapper t ~f:(fun () ->
      match Ffi.Ssl.read t.ssl ~buf:(bptr t) ~len:(blen t) with
      | Error _ as e -> e
      | Ok amount_read ->
        read_as_str := Bigstring.to_string ~len:amount_read t.bstr;
        Ok amount_read)
    >>| function
    | Ok _ ->
      if verbose
      then Debug.amf _here_ "%s: END do_ssl_read. Got: %s" t.name !read_as_str;
      Some !read_as_str
    | Error (`Stream_eof | `Session_closed) ->
      if verbose then Debug.amf _here_ "%s: END do_ssl_read. Stream closed." t.name;
      None
  ;;

  let do_ssl_write t str =
    if verbose then Debug.amf _here_ "%s: BEGIN do_ssl_write" t.name;
    let len = String.length str in
    let rec go startidx =
      if startidx >= len
      then begin
        if verbose
        then Debug.amf _here_ "%s: startidx >= len (startidx=%i, len=%i)"
               t.name startidx len;
        return ()
      end
      else begin
        in_retry_wrapper t ~f:(fun () ->
          let write_len = len - startidx in
          let substr = String.sub ~pos:startidx ~len:write_len str in
          if verbose then Debug.amf _here_ "%s: trying to ssl_write '%s'" t.name substr;
          Ffi.Ssl.write t.ssl ~buf:substr ~len:write_len)
        >>= function
        | Ok amount_written ->
          if verbose then Debug.amf _here_ "%s: wrote %i bytes" t.name amount_written;
          write_pending_to_net t
          >>= fun () ->
          go (startidx + amount_written)
        | Error e -> (* should never happen *)
          failwiths "Unexpected SSL error during write."
            e <:sexp_of< [`Session_closed | `Stream_eof ] >>
      end
    in
    go 0
  ;;

  (* Runs the net -> ssl -> app data pump until either net_to_ssl or ssl_to_app
     dies *)
  let rec run_reader_loop t =
    if verbose then Debug.amf _here_ "%s: BEGIN run_reader_loop" t.name;
    do_ssl_read t
    >>= function
    | None ->
      (* hit end of ssl_to_app in do_ssl_read *)
      return ()
    | Some s ->
      if Pipe.is_closed t.ssl_to_app
      then begin
        if verbose then Debug.amf _here_ "%s: ssl_to_app is closed; skipping write." t.name;
        return ()
      end
      else begin
        if verbose then Debug.amf _here_ "%s: ssl_to_app <- '%s'" t.name s;
        Pipe.write t.ssl_to_app s
        >>= fun () ->
        run_reader_loop t
      end
  ;;

  (* Runs the app -> ssl -> net data pump until either app_to_ssl or ssl_to_net dies. *)
  let rec run_writer_loop t =
    Pipe.read t.app_to_ssl
    >>= function
    | `Ok to_write ->
      if verbose then Debug.amf _here_ "%s: app_to_ssl -> '%s'" t.name to_write;
      do_ssl_write t to_write
      >>= fun () ->
      run_writer_loop t
    | `Eof ->
      write_pending_to_net t
      >>= fun () ->
      if verbose then Debug.amf _here_ "%s: closing ssl_to_net" t.name;
      Pipe.close t.ssl_to_net;
      return ()
  ;;

  let run_handshake t =
    let handshake_fn, handshake_name =
      match t.client_or_server with
      | `Client -> (Ffi.Ssl.connect, "connect")
      | `Server -> (Ffi.Ssl.accept , "accept" )
    in
    in_retry_wrapper t ~f:(fun () ->
      if verbose then Debug.amf _here_ "%s: trying to %s" t.name handshake_name;
      handshake_fn t.ssl)
    >>| function
    | Ok _ -> if verbose then Debug.amf _here_ "%s: Handshake complete!" t.name;
    | Error _ ->
      if verbose then Debug.amf _here_ "%s: Handshake failed!" t.name;
      crash_and_burn t;
  ;;

  (* Run both independent data pumps at once. *)
  let start_loops t =
    run_handshake t
    >>= fun () ->
    Deferred.all_unit
      [ run_reader_loop t
      ; run_writer_loop t
      ]
    >>| fun () ->
    if verbose then Debug.amf _here_ "%s: SSL stopped." t.name
  ;;

  let attach t =
    (* Close all pipes if exceptions leak out.  This will implicitly stop
       [run_reader_loop] and [run_writer_loop], since they'll just keep getting EOFs. *)
    Monitor.handle_errors ~name:"ssl_pipe" (fun () -> start_loops t)
      (fun msg ->
         let err_msg = Exn.sexp_of_t msg |> Sexp.to_string in
         if verbose then Debug.amf _here_ "%s: ERROR: %s" t.name err_msg;
         crash_and_burn t;
         raise msg)
  ;;
end

(* Global SSL contexts for every needed permutation of certification file/path. *)
let contexts =
  Memo.general (fun (ca_file, ca_path) ->
    let ctx = Ffi.Ssl_ctx.create_exn Version.Tlsv1 in
    begin match ca_file, ca_path with
      | None, None -> return (Ok ())
      | _, _       -> Ffi.Ssl_ctx.load_verify_locations ctx ?ca_file ?ca_path
    end
    >>| function
      | Error e -> Error e
      | Ok ()   -> Ok ctx)
;;

let context_exn arg =
  contexts arg
  >>| function
  | Ok context -> context
  | Error e -> failwiths "Could not initialize ssl context" e <:sexp_of< Error.t >>
;;

let default_version = Version.Tlsv1

let client ?version:(version = default_version) ?name ?ca_file ?ca_path
      ~app_to_ssl ~ssl_to_app ~net_to_ssl ~ssl_to_net () =
  context_exn (ca_file, ca_path)
  >>= fun context ->
  Connection.attach (Connection.create_client_exn ?name context version
                       ~app_to_ssl ~ssl_to_app ~net_to_ssl ~ssl_to_net)
;;

let server ?version:(version = default_version) ?name ?ca_file ?ca_path
      ~crt_file ~key_file
      ~app_to_ssl ~ssl_to_app ~net_to_ssl ~ssl_to_net () =
  context_exn (ca_file, ca_path)
  >>= fun context ->
  Connection.create_server_exn ?name context version ~crt_file ~key_file
    ~app_to_ssl ~ssl_to_app ~net_to_ssl ~ssl_to_net
  >>= fun conn ->
  Connection.attach conn
;;

TEST_MODULE = struct
  let pipe_to_string reader =
    Pipe.to_list reader >>| String.concat
  ;;

  let check_closed p name =
    if not (Pipe.is_closed p)
    then failwith (name ^ " was left open.")
  ;;

(*
     The pipe names are short because there's a lot of them and it got annoying to type.
     Please refer to this ascii art for an explanation.

                 client_out
     +---------+ a ----> c +-------+ e --------+
     | CLIENT  |           | SSL 1 |           |
     +---------+ b <---- d +-------+ f <----+  |
                 client_in                  |  |
                                            |  |
                server_out                  |  |
     +--------+ k ----> i +-------+ g ------+  |
     | SERVER |           | SSL 2 |            |
     +--------+ l <---- j +-------+ h <--------+
                server_in
  *)

  (* Create both a client and a server, and send hello world back and forth. *)
  TEST_UNIT =
    let run_test () =
      if verbose then Debug.amf _here_ "0";
      (* Refer to the above ascii art! *)
      let (l, j) = Pipe.create () in
      let (h, e) = Pipe.create () in
      let (c, a) = Pipe.create () in
      let (b, d) = Pipe.create () in
      let (f, g) = Pipe.create () in
      let (i, k) = Pipe.create () in
      let (client_in, client_out) = (b, a) in
      let (server_in, server_out) = (l, k) in
      if verbose then Debug.amf _here_ "1";
      (* attach the server to ssl 2 to net *)
      let server_done =
        server
          ~name:"server"
          ~crt_file:"do_not_use_in_production.crt"
          ~key_file:"do_not_use_in_production.key"
          ~app_to_ssl:i
          ~ssl_to_app:j
          ~ssl_to_net:g
          ~net_to_ssl:h
          ()
      in
      (* attach the client to ssl 1 to net *)
      let client_done =
        client
          ~name:"client"
          ~app_to_ssl:c
          ~ssl_to_app:d
          ~ssl_to_net:e
          ~net_to_ssl:f
          ()
      in
      if verbose then Debug.amf _here_ "2";
      Pipe.write client_out "hello, server." |> don't_wait_for;
      if verbose then Debug.amf _here_ "3";
      Pipe.close client_out;
      if verbose then Debug.amf _here_ "4";
      Pipe.write server_out "hello, client." |> don't_wait_for;
      if verbose then Debug.amf _here_ "5";
      Pipe.close server_out;
      if verbose then Debug.amf _here_ "6";
      pipe_to_string server_in
      >>= fun on_server ->
      if verbose then Debug.amf _here_ "7";
      pipe_to_string client_in
      >>= fun on_client ->
      if verbose then Debug.amf _here_ "8";
      if on_server <> "hello, server."
      then failwiths "No hello world to server" on_server <:sexp_of< string >>;
      if verbose then Debug.amf _here_ "9";
      if on_client <> "hello, client."
      then failwiths "No hello world to client" on_client <:sexp_of< string >>;
      if verbose then Debug.amf _here_ "10";
      (* check that all the pipes are closed *)
      check_closed a "client_in";
      check_closed b "client_out";
      check_closed c "c";
      check_closed d "d";
      check_closed e "e";
      check_closed f "f";
      check_closed g "g";
      check_closed h "h";
      check_closed i "i";
      check_closed j "j";
      check_closed k "server_in";
      check_closed l "server_out";
      if verbose then Debug.amf _here_ "11";
      client_done
      >>= fun () ->
      server_done
    in
    Thread_safe.block_on_async_exn run_test
  ;;

  BENCH "ssl_stress_test" =
  let run_bench () =
    (* Refer to the above ascii art! *)
    let (l, j) = Pipe.create () in
    let (h, e) = Pipe.create () in
    let (c, a) = Pipe.create () in
    let (b, d) = Pipe.create () in
    let (f, g) = Pipe.create () in
    let (i, k) = Pipe.create () in
    let (client_in, client_out) = (b, a) in
    let (server_in, server_out) = (l, k) in
    (* attach the server to ssl 2 to net *)
    let server_done =
      server
        ~name:"server"
        ~crt_file:"do_not_use_in_production.crt"
        ~key_file:"do_not_use_in_production.key"
        ~app_to_ssl:i
        ~ssl_to_app:j
        ~ssl_to_net:g
        ~net_to_ssl:h
        ()
    in
    (* attach the client to ssl 1 to net *)
    let client_done =
      client
        ~name:"client"
        ~app_to_ssl:c
        ~ssl_to_app:d
        ~ssl_to_net:e
        ~net_to_ssl:f
        ()
    in
    let rec cycle k =
      if k = 0 then begin
        Pipe.close client_out;
        Pipe.close server_out;
        return ()
      end else begin
        Pipe.write client_out "hello server"
        >>= fun () ->
        Pipe.read server_in
        >>= function
        | `Eof -> assert false
        | `Ok s -> begin
            assert (s = "hello server");
            Pipe.write server_out "hello client"
          end
          >>= fun () ->
          Pipe.read client_in
          >>= function
          | `Eof -> assert false
          | `Ok s -> begin
              assert (s = "hello client");
              return ()
            end
            >>= fun () ->
            cycle (k-1)
      end
    in
    cycle 1_000
    >>= fun () ->
    client_done
    >>= fun () ->
    server_done
  in
  Thread_safe.block_on_async_exn run_bench
;;

end
