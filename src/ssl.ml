open Core
open Poly
open Async
open Import
module Version = Version
module Opt = Opt
module Verify_mode = Verify_mode

module For_testing = struct
  let slow_down_io_to_exhibit_truncation_bugs = ref false
end

module type Ffi = module type of Ffi__library_must_be_initialized

let ffi =
  lazy
    (Initialize.initialize ();
     (module Ffi__library_must_be_initialized : Ffi))
;;

let secure_ciphers =
  [ (* from: cipherli.st *) "EECDH+AESGCM"; "EDH+AESGCM"; "AES256+EECDH"; "AES256+EDH" ]
;;

module Certificate = struct
  type t = Ffi__library_must_be_initialized.X509.t

  let subject t =
    let (module Ffi) = force ffi in
    let open Ffi in
    let subject = X509.get_subject_name t in
    let count = X509_name.entry_count subject in
    List.init count ~f:(fun i ->
      let entry = X509_name.get_entry subject i in
      let sn =
        X509_name_entry.get_object entry |> ASN1_object.obj2nid |> ASN1_object.nid2sn
      in
      let data = X509_name_entry.get_data entry |> ASN1_string.data in
      sn, data)
  ;;

  let subject_alt_names t =
    let (module Ffi) = force ffi in
    Ffi.X509.get_subject_alt_names t
  ;;
end

module Connection = struct
  type t =
    { ssl : Ffi__library_must_be_initialized.Ssl.t
    ; ctx : Ffi__library_must_be_initialized.Ssl_ctx.t
    ; client_or_server : [ `Client | `Server ]
    (* The reader and writer binary IO interfaces used by SSL to exchange data without
       going through a file descriptor.  Strangely enough, to use SSL we _read from_ wbio
       and _write to_ wbio.  The names are from the perspective of the SSL library. *)
    ; rbio : Ffi__library_must_be_initialized.Bio.t
    ; wbio : Ffi__library_must_be_initialized.Bio.t
    (* Reads and writes to/from C must go through a bigstring.  We share it in the record
       to prevent needless reallocations. *)
    ; bstr : bigstring
    ; name : string
    ; app_to_ssl : string Pipe.Reader.t
    ; ssl_to_app : string Pipe.Writer.t
    ; net_to_ssl : string Pipe.Reader.t
    ; ssl_to_net : string Pipe.Writer.t
    ; closed : unit Or_error.t Ivar.t
    }
  [@@deriving sexp_of, fields]

  let tmp_rsa =
    let exponent = 65537 (* small random odd (prime?), e.g. 3, 17 or 65537 *) in
    Memo.general ~hashable:Int.hashable (fun key_length ->
      let (module Ffi) = force ffi in
      Ffi.Rsa.generate_key ~key_length ~exponent ())
  ;;

  let tmp_ecdh =
    lazy
      (let (module Ffi) = force ffi in
       let curve = Ffi.Ec_key.Curve.prime256v1 in
       Ffi.Ec_key.new_by_curve_name curve)
  ;;

  let tmp_dh_callback =
    lazy
      (* To ensure that the underlying libffi closure is not released pre-maturely
         we create (and never free) a [Foreign.dynamic_funptr] here.
         This does not leak as only 2 callbacks are ever defined. *)
      (let (module Ffi) = force ffi in
       Ffi.Ssl.Tmp_dh_callback.of_fun (fun _t _is_export key_length ->
         Rfc3526.modp key_length))
  ;;

  let tmp_rsa_callback =
    lazy
      (* Like [tmp_dh_callback]. *)
      (let (module Ffi) = force ffi in
       Ffi.Ssl.Tmp_rsa_callback.of_fun (fun _t _is_export key_length ->
         tmp_rsa key_length))
  ;;

  let create_exn
        ?verify_modes
        ?(allowed_ciphers = `Secure)
        ctx
        version
        client_or_server
        ?hostname
        name
        ~app_to_ssl
        ~ssl_to_app
        ~net_to_ssl
        ~ssl_to_net
    =
    let (module Ffi) = force ffi in
    (* SSL is transferred in 16 kB packets.  Therefore, it makes sense for our buffers to
       be the same size. *)
    let ssl = Ffi.Ssl.create_exn ctx in
    Option.value_map hostname ~default:() ~f:(fun h ->
      Ffi.Ssl.set_tlsext_host_name ssl h |> Or_error.ok_exn);
    Ffi.Ssl.set_method ssl version;
    let rbio = Ffi.Bio.create () in
    let wbio = Ffi.Bio.create () in
    let default_buffer_size = 16 * 1024 in
    let bstr = Bigstring.create default_buffer_size in
    (* The default used to be [Verify_none] which defers the decision to abort the
       connection to the caller. The caller must be careful to check that the certificate
       verified correctly. To prevent mistakes, we've changed it to [Verify_peer]. *)
    Option.iter verify_modes ~f:(Ffi.Ssl.set_verify ssl);
    (match allowed_ciphers with
     | `Openssl_default -> ()
     | `Secure -> Ffi.Ssl.set_cipher_list_exn ssl secure_ciphers
     | `Only allowed_ciphers -> Ffi.Ssl.set_cipher_list_exn ssl allowed_ciphers);
    Ffi.Ssl.set_tmp_dh_callback ssl (force tmp_dh_callback);
    Ffi.Ssl.set_tmp_ecdh ssl (force tmp_ecdh);
    (* Ffi.Ssl.set_tmp_rsa_callback ssl (force tmp_rsa_callback); *)
    Ffi.Ssl.set_bio ssl ~input:rbio ~output:wbio;
    let closed = Ivar.create () in
    { ssl
    ; client_or_server
    ; rbio
    ; wbio
    ; bstr
    ; name
    ; app_to_ssl
    ; ssl_to_app
    ; net_to_ssl
    ; ssl_to_net
    ; closed
    ; ctx
    }
  ;;

  let create_client_exn
        ?hostname
        ?name:(nm = "(anonymous)")
        ?allowed_ciphers
        ?(verify_modes = [ Verify_mode.Verify_peer ])
        ctx
        version
        ~app_to_ssl
        ~ssl_to_app
        ~net_to_ssl
        ~ssl_to_net
    =
    create_exn
      ~verify_modes
      ?allowed_ciphers
      ctx
      version
      `Client
      ?hostname
      nm
      ~app_to_ssl
      ~ssl_to_app
      ~net_to_ssl
      ~ssl_to_net
    |> return
  ;;

  let create_server_exn
        ?name:(nm = "(anonymous)")
        ?verify_modes
        ?allowed_ciphers
        ctx
        version
        ~app_to_ssl
        ~ssl_to_app
        ~net_to_ssl
        ~ssl_to_net
    =
    let (module Ffi) = force ffi in
    let connection =
      create_exn
        ?verify_modes
        ?allowed_ciphers
        ctx
        version
        `Server
        nm
        ~app_to_ssl
        ~ssl_to_app
        ~net_to_ssl
        ~ssl_to_net
    in
    Or_error.ok_exn (Ffi.Ssl.check_private_key connection.ssl);
    return connection
  ;;

  let raise_with_ssl_errors () =
    let (module Ffi) = force ffi in
    failwiths ~here:[%here] "Ssl_error" (Ffi.get_error_stack ()) [%sexp_of: string list]
  ;;

  let closed t = Ivar.read t.closed

  let version t =
    let (module Ffi) = force ffi in
    Ffi.Ssl.get_version t.ssl
  ;;

  let session_reused t =
    let (module Ffi) = force ffi in
    Ffi.Ssl.session_reused t.ssl
  ;;

  let peer_certificate t =
    let (module Ffi) = force ffi in
    match Ffi.Ssl.get_peer_certificate t.ssl with
    | None -> None
    | Some cert ->
      (match Ffi.Ssl.get_verify_result t.ssl with
       | Ok () -> Some (Ok cert)
       | Error e -> Some (Error e))
  ;;

  let pem_peer_certificate_chain t =
    let (module Ffi) = force ffi in
    Ffi.Ssl.get_peer_certificate_chain t.ssl
  ;;

  let blen t = Bigstring.length t.bstr
  let bptr t = Ctypes.bigarray_start Ctypes.array1 t.bstr

  (* Called when something goes horribly wrong. This makes sure that
     resources don't leak when exceptional circumstances hit.

     The SSL structure itself is freed by the GC finalizer.
  *)
  let cleanup t =
    if verbose then Debug.amf [%here] "%s: cleanup" t.name;
    Pipe.close_read t.app_to_ssl;
    Pipe.close t.ssl_to_app;
    Pipe.close_read t.net_to_ssl;
    Pipe.close t.ssl_to_net
  ;;

  let close t = cleanup t

  (* Write any pending data to ssl_to_net.  If you bind to the returned [unit Deferred.t],
     you wait until the write has completed all the way through the pipe to the end.

     This drains wbio whether or not ssl_to_net is closed or not.  When ssl_to_net IS
     closed, we make sure to close its matching partner: app_to_ssl. *)
  let rec write_pending_to_net t =
    let (module Ffi) = force ffi in
    if verbose then Debug.amf [%here] "%s: write_pending_to_net" t.name;
    let amount_read = Ffi.Bio.read t.wbio ~buf:(bptr t) ~len:(blen t) in
    if verbose then Debug.amf [%here] "%s:   amount_read: %i" t.name amount_read;
    if amount_read < 0
    then (
      if verbose then Debug.amf [%here] "%s: write_pending_to_net complete" t.name;
      return ())
    else if amount_read = 0
    then write_pending_to_net t
    else (
      let to_write = Bigstring.to_string ~len:amount_read t.bstr in
      let%bind () =
        if not (Pipe.is_closed t.ssl_to_net)
        then (
          if verbose then Debug.amf [%here] "%s: ssl_to_net <- '%s'" t.name to_write;
          if !For_testing.slow_down_io_to_exhibit_truncation_bugs
          then (
            let%bind () = Clock.after (Time.Span.of_sec 0.001) in
            Pipe.write t.ssl_to_net to_write)
          else Pipe.write t.ssl_to_net to_write)
        else (
          if verbose then Debug.amf [%here] "%s: closing app_to_ssl" t.name;
          Pipe.close_read t.app_to_ssl;
          return ())
      in
      write_pending_to_net t)
  ;;

  let flush t =
    if verbose then Debug.amf [%here] "%s: Flushing..." t.name;
    let%bind () = write_pending_to_net t in
    let%bind _ = Pipe.upstream_flushed t.ssl_to_net in
    if verbose then Debug.amf [%here] "%s: Done flush." t.name;
    return ()
  ;;

  (* Runs an ssl function (either ssl_read or ssl_write), possibly retrying the call if
     an error was returned. *)
  let rec in_retry_wrapper
    : type a. t -> f:(unit -> (a, _) Result.t) -> (a, _) Result.t Deferred.t
    =
    fun t ~f ->
      let (module Ffi) = force ffi in
      let ret = f () in
      let module E = Ffi.Ssl_error in
      match ret with
      | Ok x -> return (Ok x)
      | Error e ->
        if verbose then Debug.amf [%here] "%s: %s" t.name (E.sexp_of_t e |> Sexp.to_string);
        (match e with
         | E.Want_read ->
           (* [Un]intuitively enough, if SSL wants a read, we need to write out all
              pending data first. *)
           let%bind () = flush t in
           (* Then, write the chunk of data from the net into the rbio and try again. *)
           (match%bind Pipe.read t.net_to_ssl with
            | `Ok was_read ->
              Ffi.Bio.write t.rbio ~buf:was_read ~len:(String.length was_read) |> ignore;
              (* Should never fail. It's an 'infinite' buffer. *)
              in_retry_wrapper t ~f
            (* If the connection to the net died, we have to stop. Return an error,
               and close its matching pipe. *)
            | `Eof ->
              if verbose then Debug.amf [%here] "%s: closing ssl_to_app" t.name;
              Pipe.close t.ssl_to_app;
              return (Error `Stream_eof))
         | E.Want_write ->
           (* If SSL requests a write, write and try again. *)
           let%bind () = flush t in
           in_retry_wrapper t ~f
         (* If the underlying SSL connection died, we get an error of 'ZeroReturn'. *)
         | E.Zero_return -> return (Error `Session_closed)
         (* And of course, sometimes SSL is just broken. *)
         | E.Ssl_error
         | E.Want_connect
         | E.Want_accept
         | E.Want_X509_lookup
         | E.Syscall_error -> raise_with_ssl_errors ())
  ;;

  let do_ssl_read t =
    let (module Ffi) = force ffi in
    if verbose then Debug.amf [%here] "%s: BEGIN do_ssl_read" t.name;
    let read_as_str = ref "" in
    match%map
      in_retry_wrapper t ~f:(fun () ->
        match Ffi.Ssl.read t.ssl ~buf:(bptr t) ~len:(blen t) with
        | Error _ as e -> e
        | Ok amount_read ->
          read_as_str := Bigstring.to_string ~len:amount_read t.bstr;
          Ok amount_read)
    with
    | Ok _ ->
      if verbose then Debug.amf [%here] "%s: END do_ssl_read. Got: %s" t.name !read_as_str;
      Some !read_as_str
    | Error (`Stream_eof | `Session_closed) ->
      if verbose then Debug.amf [%here] "%s: END do_ssl_read. Stream closed." t.name;
      None
  ;;

  let do_ssl_write t str =
    let (module Ffi) = force ffi in
    if verbose then Debug.amf [%here] "%s: BEGIN do_ssl_write" t.name;
    let len = String.length str in
    let rec go startidx =
      if startidx >= len
      then (
        if verbose
        then
          Debug.amf
            [%here]
            "%s: startidx >= len (startidx=%i, len=%i)"
            t.name
            startidx
            len;
        return ())
      else (
        match%bind
          in_retry_wrapper t ~f:(fun () ->
            let write_len = len - startidx in
            let substr = String.sub ~pos:startidx ~len:write_len str in
            if verbose
            then Debug.amf [%here] "%s: trying to ssl_write '%s'" t.name substr;
            Ffi.Ssl.write t.ssl ~buf:substr ~len:write_len)
        with
        | Ok amount_written ->
          if verbose then Debug.amf [%here] "%s: wrote %i bytes" t.name amount_written;
          let%bind () = write_pending_to_net t in
          go (startidx + amount_written)
        | Error e ->
          (* should never happen *)
          failwiths
            ~here:[%here]
            "Unexpected SSL error during write."
            e
            [%sexp_of: [ `Session_closed | `Stream_eof ]])
    in
    go 0
  ;;

  (* Runs the net -> ssl -> app data pump until either net_to_ssl or ssl_to_app
     dies *)
  let rec run_reader_loop t =
    if verbose then Debug.amf [%here] "%s: BEGIN run_reader_loop" t.name;
    match%bind do_ssl_read t with
    | None ->
      (* we hit end of t.ssl in do_ssl_read, close ssl_to_app so the app sees the close *)
      return (Pipe.close t.ssl_to_app)
    | Some s ->
      if Pipe.is_closed t.ssl_to_app
      then (
        if verbose
        then Debug.amf [%here] "%s: ssl_to_app is closed; skipping write." t.name;
        return ())
      else (
        if verbose then Debug.amf [%here] "%s: ssl_to_app <- '%s'" t.name s;
        let%bind () = Pipe.write t.ssl_to_app s in
        run_reader_loop t)
  ;;

  (* Runs the app -> ssl -> net data pump until either app_to_ssl or ssl_to_net dies. *)
  let rec run_writer_loop t =
    match%bind Pipe.read t.app_to_ssl with
    | `Ok to_write ->
      if verbose then Debug.amf [%here] "%s: app_to_ssl -> '%s'" t.name to_write;
      let%bind () = do_ssl_write t to_write in
      run_writer_loop t
    | `Eof ->
      let%bind () = write_pending_to_net t in
      if verbose then Debug.amf [%here] "%s: closing ssl_to_net" t.name;
      Pipe.close t.ssl_to_net;
      return ()
  ;;

  let run_handshake t =
    let (module Ffi) = force ffi in
    let handshake_fn, handshake_name =
      match t.client_or_server with
      | `Client -> Ffi.Ssl.connect, "connect"
      | `Server -> Ffi.Ssl.accept, "accept"
    in
    match%map
      in_retry_wrapper t ~f:(fun () ->
        if verbose then Debug.amf [%here] "%s: trying to %s" t.name handshake_name;
        handshake_fn t.ssl)
    with
    | Ok _ -> if verbose then Debug.amf [%here] "%s: Handshake complete!" t.name
    | Error _ ->
      if verbose then Debug.amf [%here] "%s: Handshake failed!" t.name;
      cleanup t
  ;;

  (* Run both independent data pumps at once. *)
  let start_loops t =
    let%map () = Deferred.all_unit [ run_reader_loop t; run_writer_loop t ] in
    if verbose then Debug.amf [%here] "%s: SSL stopped." t.name
  ;;

  (* Close all pipes if exceptions leak out.  This will implicitly stop
     [run_reader_loop] and [run_writer_loop], since they'll just keep getting EOFs. *)
  let with_cleanup t ~f =
    let%map result = Deferred.Or_error.try_with ~name:"ssl_pipe" f in
    Result.iter_error result ~f:(fun error ->
      if verbose
      then Debug.amf [%here] "%s: ERROR: %s" t.name (Error.to_string_hum error);
      cleanup t);
    result
  ;;
end

module Session = struct
  module State = struct
    type t =
      { session : Ffi__library_must_be_initialized.Ssl_session.t
      (* One SSL_SESSION object must only be used with one SSL_CTX object *)
      ; ctx : Ffi__library_must_be_initialized.Ssl_ctx.t
      }

    let get ~conn =
      let (module Ffi) = force ffi in
      match Ffi.Ssl.get1_session (Connection.ssl conn) with
      | None ->
        if verbose
        then
          Debug.amf
            [%here]
            "no session available for connection %s"
            (Connection.name conn);
        None
      | Some session -> Some { session; ctx = Connection.ctx conn }
    ;;

    let reuse t ~conn =
      let (module Ffi) = force ffi in
      if not (phys_equal t.ctx (Connection.ctx conn))
      then
        failwithf
          "Trying to reuse %s with a different context (did you change ca_file or \
           ca_path?)"
          (Connection.name conn)
          ();
      Ffi.Ssl.set_session (Connection.ssl conn) t.session |> Or_error.ok_exn
    ;;
  end

  type t = State.t Set_once.t

  let create () = Set_once.create ()

  let remember t ~conn =
    match Set_once.get t with
    | Some _ -> ()
    | None -> Option.iter (State.get ~conn) ~f:(Set_once.set_exn t [%here])
  ;;

  let reuse t ~conn = Option.iter (Set_once.get t) ~f:(State.reuse ~conn)
end

(* Global SSL contexts for every needed
   (name, version, ca_file, ca_path, options, crt_file, key_file)
   tuple. This is cached so that the same SSL_CTX object can be reused later *)
let context_exn =
  Memo.general (fun (name, version, ca_file, ca_path, options, crt_file, key_file) ->
    let (module Ffi) = force ffi in
    let ctx = Ffi.Ssl_ctx.create_exn version in
    let error e =
      failwiths ~here:[%here] "Could not initialize ssl context" e [%sexp_of: Error.t]
    in
    match%bind
      match crt_file, key_file with
      | Some crt_file, Some key_file ->
        Ffi.Ssl_ctx.use_certificate_chain_and_key_files ~crt_file ~key_file ctx
      | _, _ -> return (Ok ())
    with
    | Error e -> error e
    | Ok () ->
      (match%map
         match ca_file, ca_path with
         | None, None -> return (Ok (Ffi.Ssl_ctx.set_default_verify_paths ctx))
         | _, _ -> Ffi.Ssl_ctx.load_verify_locations ctx ?ca_file ?ca_path
       with
       | Error e -> error e
       | Ok () ->
         let session_id_context =
           Option.value name ~default:"default_session_id_context"
         in
         Ffi.Ssl_ctx.set_session_id_context ctx session_id_context;
         Ffi.Ssl_ctx.set_options ctx options;
         ctx))
;;

let client
      ?(version = Version.default)
      ?(options = Opt.default)
      ?name
      ?hostname
      ?allowed_ciphers
      ?ca_file
      ?ca_path
      ?crt_file
      ?key_file
      ?verify_modes
      ?session
      ~app_to_ssl
      ~ssl_to_app
      ~net_to_ssl
      ~ssl_to_net
      ()
  =
  Deferred.Or_error.try_with (fun () ->
    let%bind context =
      context_exn (name, version, ca_file, ca_path, options, crt_file, key_file)
    in
    Connection.create_client_exn
      ?hostname
      ?name
      ?verify_modes
      ?allowed_ciphers
      context
      version
      ~app_to_ssl
      ~ssl_to_app
      ~net_to_ssl
      ~ssl_to_net)
  >>=? fun conn ->
  Option.iter session ~f:(Session.reuse ~conn);
  Connection.with_cleanup conn ~f:(fun () -> Connection.run_handshake conn)
  >>=? fun () ->
  Option.iter session ~f:(Session.remember ~conn);
  don't_wait_for
    (Connection.with_cleanup conn ~f:(fun () -> Connection.start_loops conn)
     >>| Ivar.fill conn.closed);
  return (Ok conn)
;;

let server
      ?(version = Version.default)
      ?(options = Opt.default)
      ?name
      ?allowed_ciphers
      ?ca_file
      ?ca_path
      ~crt_file
      ~key_file
      ?verify_modes
      ~app_to_ssl
      ~ssl_to_app
      ~net_to_ssl
      ~ssl_to_net
      ()
  =
  Deferred.Or_error.try_with (fun () ->
    let%bind context =
      context_exn
        (name, version, ca_file, ca_path, options, Some crt_file, Some key_file)
    in
    Connection.create_server_exn
      ?name
      context
      version
      ?verify_modes
      ?allowed_ciphers
      ~app_to_ssl
      ~ssl_to_app
      ~net_to_ssl
      ~ssl_to_net)
  >>=? fun conn ->
  Connection.with_cleanup conn ~f:(fun () -> Connection.run_handshake conn)
  >>=? fun () ->
  don't_wait_for
    (Connection.with_cleanup conn ~f:(fun () -> Connection.start_loops conn)
     >>| Ivar.fill conn.closed);
  return (Ok conn)
;;

let%test_module _ =
  (module struct
    let pipe_to_string reader = Pipe.to_list reader >>| String.concat

    let check_closed p name =
      if not (Pipe.is_closed p) then failwith (name ^ " was left open.")
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
    let with_pipes ~f =
      let func = f in
      if verbose then Debug.amf [%here] "creating pipes";
      let l, j = Pipe.create () in
      let h, e = Pipe.create () in
      let c, a = Pipe.create () in
      let b, d = Pipe.create () in
      let f, g = Pipe.create () in
      let i, k = Pipe.create () in
      func ~a ~b ~c ~d ~e ~f ~g ~h ~i ~j ~k ~l
    ;;

    (* Create both a client and a server, and send hello world back and forth. *)
    let%test_unit _ =
      let session = Session.create () in
      let check_version conn =
        (* Since Version.default is [Sslv23], we expect to negotiate the highest allowed
           protocol version, which is [Tlsv1_2] *)
        [%test_result: Version.t] (Connection.version conn) ~expect:Version.Tlsv1_2
      in
      let check_session_reused conn ~expect =
        [%test_result: bool] (Connection.session_reused conn) ~expect
      in
      let check_peer_certificate conn =
        let cert =
          Connection.peer_certificate conn |> Option.value_exn |> Or_error.ok_exn
        in
        let value =
          let alist = Certificate.subject cert in
          List.Assoc.find_exn alist ~equal:String.equal "CN"
        in
        [%test_result: string] value ~expect:"testbox"
      in
      let run_test ~expect_session_reused =
        with_pipes ~f:(fun ~a ~b ~c ~d ~e ~f ~g ~h ~i ~j ~k ~l ->
          let client_in, client_out = b, a in
          let server_in, server_out = l, k in
          if verbose then Debug.amf [%here] "1";
          (* attach the server to ssl 2 to net *)
          let server_conn =
            server
              ~name:
                "server"
              (* It might be confusing that the two "don't_use_in_production"
                 files are used for different purposes. This is enough to test out
                 the functionality, but if we want to be super clear we need 5
                 such files in this library: ca crt, server key + crt, and client
                 key + crt.*)
              ~allowed_ciphers:`Secure
              ~ca_file:"do_not_use_in_production.crt" (* CA certificate *)
              ~crt_file:"do_not_use_in_production.crt" (* server certificate *)
              ~key_file:"do_not_use_in_production.key" (* server key *)
              ~verify_modes:[ Verify_mode.Verify_peer ]
              ~app_to_ssl:i
              ~ssl_to_app:j
              ~ssl_to_net:g
              ~net_to_ssl:h
              ()
          in
          let client_conn =
            client
              ~name:
                "client" (* Necessary to verify the self-signed server certificate. *)
              ~allowed_ciphers:`Secure
              ~ca_file:"do_not_use_in_production.crt" (* ca certificate *)
              ~crt_file:"do_not_use_in_production.crt" (* client certificate *)
              ~key_file:"do_not_use_in_production.key" (* client key *)
              ~hostname:"does-not-matter"
              ~session
              ~app_to_ssl:c
              ~ssl_to_app:d
              ~ssl_to_net:e
              ~net_to_ssl:f
              ()
          in
          let client_conn = client_conn >>| Or_error.ok_exn in
          let server_conn = server_conn >>| Or_error.ok_exn in
          let%bind client_conn, server_conn = Deferred.both client_conn server_conn in
          check_version client_conn;
          check_version server_conn;
          if verbose then Debug.amf [%here] "client checking server certificate";
          check_peer_certificate client_conn;
          if verbose then Debug.amf [%here] "server checking client certificate";
          check_peer_certificate server_conn;
          if verbose then Debug.amf [%here] "client checking reused";
          check_session_reused client_conn ~expect:expect_session_reused;
          if verbose then Debug.amf [%here] "server checking reused";
          check_session_reused server_conn ~expect:expect_session_reused;
          if verbose then Debug.amf [%here] "2";
          Pipe.write client_out "hello, server." |> don't_wait_for;
          if verbose then Debug.amf [%here] "3";
          Pipe.close client_out;
          if verbose then Debug.amf [%here] "4";
          Pipe.write server_out "hello, client." |> don't_wait_for;
          if verbose then Debug.amf [%here] "5";
          Pipe.close server_out;
          if verbose then Debug.amf [%here] "6";
          let%bind on_server = pipe_to_string server_in in
          if verbose then Debug.amf [%here] "7";
          let%bind on_client = pipe_to_string client_in in
          if verbose then Debug.amf [%here] "8";
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
          if verbose then Debug.amf [%here] "9";
          let%bind client_exit_status = Connection.closed client_conn in
          Or_error.ok_exn client_exit_status;
          let%bind server_exit_status = Connection.closed server_conn in
          Or_error.ok_exn server_exit_status;
          if on_server <> "hello, server."
          then
            failwiths
              ~here:[%here]
              "No hello world to server"
              on_server
              [%sexp_of: string];
          if on_client <> "hello, client."
          then
            failwiths
              ~here:[%here]
              "No hello world to client"
              on_client
              [%sexp_of: string];
          return ())
      in
      let run_twice () =
        if verbose then Debug.amf [%here] "first run";
        let%bind () = run_test ~expect_session_reused:false in
        if verbose then Debug.amf [%here] "second run";
        run_test ~expect_session_reused:true
      in
      Thread_safe.block_on_async_exn run_twice
    ;;

    let%bench "ssl_stress_test" =
      let run_bench () =
        with_pipes ~f:(fun ~a ~b ~c ~d ~e ~f ~g ~h ~i ~j ~k ~l ->
          let client_in, client_out = b, a in
          let server_in, server_out = l, k in
          (* attach the server to ssl 2 to net *)
          let server_conn =
            server
              ~name:"server"
              ~allowed_ciphers:`Secure
              ~crt_file:"do_not_use_in_production.crt"
              ~key_file:"do_not_use_in_production.key"
              ~app_to_ssl:i
              ~ssl_to_app:j
              ~ssl_to_net:g
              ~net_to_ssl:h
              ()
          in
          (* attach the client to ssl 1 to net *)
          let client_conn =
            client
              ~name:"client"
              ~allowed_ciphers:`Secure
              ~app_to_ssl:c
              ~ssl_to_app:d
              ~ssl_to_net:e
              ~net_to_ssl:f
              ()
          in
          let%bind client_conn, server_conn = Deferred.both client_conn server_conn in
          let client_conn = Or_error.ok_exn client_conn in
          let server_conn = Or_error.ok_exn server_conn in
          let rec cycle k =
            if k = 0
            then (
              Pipe.close client_out;
              Pipe.close server_out;
              return ())
            else (
              let%bind () = Pipe.write client_out "hello server" in
              match%bind Pipe.read server_in with
              | `Eof -> assert false
              | `Ok s ->
                let%bind () =
                  assert (s = "hello server");
                  Pipe.write server_out "hello client"
                in
                (match%bind Pipe.read client_in with
                 | `Eof -> assert false
                 | `Ok s ->
                   let%bind () =
                     assert (s = "hello client");
                     return ()
                   in
                   cycle (k - 1)))
          in
          let%bind () = cycle 1_000 in
          let%bind client_exit_status = Connection.closed client_conn in
          Or_error.ok_exn client_exit_status;
          let%bind server_exit_status = Connection.closed server_conn in
          Or_error.ok_exn server_exit_status;
          return ())
      in
      Thread_safe.block_on_async_exn run_bench
    ;;
  end)
;;
