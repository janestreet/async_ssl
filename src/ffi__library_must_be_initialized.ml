open Core
open Poly
open Async
open Import
module Ssl_method = Bindings.Ssl_method

module Ssl_error = struct
  type t =
    | Zero_return
    | Want_read
    | Want_write
    | Want_connect
    | Want_accept
    | Want_X509_lookup
    | Syscall_error
    | Ssl_error
  [@@deriving sexp_of]

  let of_int n =
    let open Types.Ssl_error in
    if n = none
    then Ok ()
    else if n = zero_return
    then Error Zero_return
    else if n = want_read
    then Error Want_read
    else if n = want_write
    then Error Want_write
    else if n = want_connect
    then Error Want_connect
    else if n = want_accept
    then Error Want_accept
    else if n = want_x509_lookup
    then Error Want_X509_lookup
    else if n = syscall
    then Error Syscall_error
    else if n = ssl
    then Error Ssl_error
    else failwithf "Unrecognized result of SSL_get_error: %d" n ()
  ;;
end

module Verify_mode = struct
  include Verify_mode

  let to_int t =
    let open Types.Verify_mode in
    match t with
    | Verify_none -> verify_none
    | Verify_peer -> verify_peer
    | Verify_fail_if_no_peer_cert -> verify_fail_if_no_peer_cert
    | Verify_client_once -> verify_client_once
  ;;
end

let bigstring_strlen bigstr =
  let len = Bigstring.length bigstr in
  let idx = ref 0 in
  while !idx < len && bigstr.{!idx} <> '\x00' do
    incr idx
  done;
  !idx
;;

let get_error_stack =
  let err_error_string =
    (* We need to write error strings from C into bigstrings. To reduce allocation, reuse
       scratch space for this. *)
    let scratch_space = Bigstring.create 1024 in
    fun err ->
      Bindings.err_error_string_n
        err
        (Ctypes.bigarray_start Ctypes.array1 scratch_space)
        (Bigstring.length scratch_space);
      Bigstring.to_string ~len:(bigstring_strlen scratch_space) scratch_space
  in
  fun () ->
    iter_while_rev ~iter:Bindings.err_get_error ~cond:(fun x -> x <> Unsigned.ULong.zero)
    |> List.rev_map ~f:err_error_string
;;

module Ssl_ctx = struct
  type t = Bindings.Ssl_ctx.t [@@deriving sexp_of]

  (* for use in ctypes type signatures *)

  let create_exn ver =
    let ver_method =
      let module V = Version in
      match ver with
      | V.Sslv23 -> Ssl_method.sslv23 ()
      | V.Tls -> Ssl_method.tls ()
      | V.Sslv3 -> Ssl_method.sslv3 ()
      | V.Tlsv1 -> Ssl_method.tlsv1 ()
      | V.Tlsv1_1 -> Ssl_method.tlsv1_1 ()
      | V.Tlsv1_2 -> Ssl_method.tlsv1_2 ()
      | V.Tlsv1_3 -> Ssl_method.tlsv1_3 ()
    in
    match Bindings.Ssl_ctx.new_ ver_method with
    | None -> failwith "Could not allocate a new SSL context."
    | Some p ->
      Gc.add_finalizer_exn p Bindings.Ssl_ctx.free;
      p
  ;;

  let override_default_insecure__set_security_level t level =
    Bindings.Ssl_ctx.override_default_insecure__set_security_level t level
  ;;

  let set_options context options =
    let module O = Types.Ssl_op in
    let default_options =
      List.fold
        [ O.single_dh_use; O.single_ecdh_use ]
        ~init:Unsigned.ULong.zero
        ~f:Unsigned.ULong.logor
    in
    let opts =
      List.fold options ~init:default_options ~f:(fun acc (opt : Opt.t) ->
        let o =
          match opt with
          | No_sslv2 -> O.no_sslv2
          | No_sslv3 -> O.no_sslv3
          | No_tlsv1 -> O.no_tlsv1
          | No_tlsv1_1 -> O.no_tlsv1_1
          | No_tlsv1_2 -> O.no_tlsv1_2
          | No_tlsv1_3 -> O.no_tlsv1_3
        in
        Unsigned.ULong.logor acc o)
    in
    (* SSL_CTX_set_options(3) returns the new options bitmask after adding options. We
       don't really have a use for this, so ignore. *)
    let (_ : Unsigned.ULong.t) = Bindings.Ssl_ctx.set_options context opts in
    ()
  ;;

  let set_session_id_context context sid_ctx =
    let session_id_ctx = Ctypes.(coerce string (ptr char)) sid_ctx in
    match
      Bindings.Ssl_ctx.set_session_id_context
        context
        session_id_ctx
        (Unsigned.UInt.of_int (String.length sid_ctx))
    with
    | 1 -> ()
    | x ->
      failwiths
        "Could not set session id context."
        (`Return_value x, `Errors (get_error_stack ()))
        [%sexp_of: [ `Return_value of int ] * [ `Errors of string list ]]
  ;;

  let load_verify_locations ?ca_file ?ca_path ctx =
    match%bind
      In_thread.run (fun () -> Bindings.Ssl_ctx.load_verify_locations ctx ca_file ca_path)
    with
    (* Yep, 1 means success. *)
    | 1 -> Deferred.return (Or_error.return ())
    | _ ->
      Deferred.return
        (match ca_file, ca_path with
         | None, None -> Or_error.error_string "No CA files given."
         | _ ->
           Or_error.error "CA load error" (get_error_stack ()) [%sexp_of: string list])
  ;;

  let set_default_verify_paths ctx =
    match Bindings.Ssl_ctx.set_default_verify_paths ctx with
    | 1 -> ()
    | x ->
      failwiths
        "Could not set default verify paths."
        (`Return_value x, `Errors (get_error_stack ()))
        [%sexp_of: [ `Return_value of int ] * [ `Errors of string list ]]
  ;;

  let try_certificate_chain_and_failover_to_asn1 ctx crt_file =
    match Bindings.Ssl_ctx.use_certificate_chain_file ctx crt_file with
    | 1 -> 1
    | _ -> Bindings.Ssl_ctx.use_certificate_file ctx crt_file Types.X509_filetype.asn1
  ;;

  let try_both_private_key_formats ctx key_file =
    match Bindings.Ssl_ctx.use_private_key_file ctx key_file Types.X509_filetype.pem with
    | 1 -> 1
    | _ -> Bindings.Ssl_ctx.use_private_key_file ctx key_file Types.X509_filetype.asn1
  ;;

  let use_certificate_chain_and_key_files ~crt_file ~key_file ctx =
    let error message return_value =
      Deferred.Or_error.error_s
        [%message
          message
            (return_value : int)
            ~errors:(get_error_stack () : string list)
            ~crt_file
            ~key_file]
    in
    match%bind
      In_thread.run (fun () -> try_certificate_chain_and_failover_to_asn1 ctx crt_file)
    with
    | 1 ->
      (match%bind In_thread.run (fun () -> try_both_private_key_formats ctx key_file) with
       | 1 -> Deferred.Or_error.return ()
       | x -> error "Could not use private key" x)
    | x -> error "Could not use certificate" x
  ;;

  let alpn_protocols_to_char_vector protocols =
    let open Ctypes in
    let count =
      List.sum (module Int) protocols ~f:String.length + List.length protocols + 1
    in
    let prots = allocate_n char ~count in
    let len =
      List.fold protocols ~init:0 ~f:(fun loc prot ->
        prots +@ loc <-@ char_of_int (String.length prot);
        String.fold prot ~init:(loc + 1) ~f:(fun loc c ->
          prots +@ loc <-@ c;
          loc + 1))
      |> Unsigned.UInt.of_int
    in
    prots, len
  ;;

  let set_alpn_protocols_client ctx protocols =
    let prot_vector, len = alpn_protocols_to_char_vector protocols in
    match%bind.Or_error
      Or_error.try_with (fun () -> Bindings.Ssl_ctx.set_alpn_protos ctx prot_vector len)
    with
    | 0 -> Or_error.return ()
    | x ->
      Or_error.error
        "Could not set alpn protocol."
        (`Return_value x, `Errors (get_error_stack ()))
        [%sexp_of: [ `Return_value of int ] * [ `Errors of string list ]]
  ;;

  let set_alpn_protocols_server ctx protocols =
    let prot_vector, len = alpn_protocols_to_char_vector protocols in
    let%map.Or_error alpn_ctx =
      Or_error.try_with (fun () -> Bindings.Ssl_ctx.set_alpn_callback ctx prot_vector len)
    in
    Gc.add_finalizer_exn ctx (fun _ -> Bindings.Ssl_ctx.free_alpn_callback alpn_ctx)
  ;;
end

module Bio = struct
  type t = Bindings.Bio.t [@@deriving sexp_of]

  (* for use in ctypes signatures *)

  let create () = Bindings.Bio.s_mem () |> Bindings.Bio.new_

  let read bio ~buf ~len =
    let retval = Bindings.Bio.read bio buf len in
    if verbose then Debug.amf [%here] "BIO_read(%i) -> %i" len retval;
    retval
  ;;

  let write bio ~buf ~len =
    let retval = Bindings.Bio.write bio buf len in
    if verbose then Debug.amf [%here] "BIO_write(%i) -> %i" len retval;
    retval
  ;;
end

module ASN1_object = struct
  type t = Bindings.ASN1_object.t

  let obj2nid = Bindings.ASN1_object.obj2nid

  let nid2sn n =
    Option.value
      (Bindings.ASN1_object.nid2sn n)
      ~default:(sprintf "unknown object nid (%d)" n)
  ;;
end

module ASN1_string = struct
  type t = Bindings.ASN1_string.t

  let data t = Bindings.ASN1_string.data t
end

module X509_name_entry = struct
  type t = Bindings.X509_name_entry.t

  let get_object = Bindings.X509_name_entry.get_object
  let get_data = Bindings.X509_name_entry.get_data
end

module X509_name = struct
  type t = Bindings.X509_name.t

  let entry_count = Bindings.X509_name.entry_count
  let get_entry = Bindings.X509_name.get_entry
end

module X509 = struct
  type t = Bindings.X509.t

  let get_subject_name t =
    match Bindings.X509.get_subject_name t with
    | Some name -> name
    | None -> failwith "Certificate contains no subject name."
  ;;

  let get_subject_alt_names t =
    let open Ctypes in
    match Bindings.X509.subject_alt_names t with
    | None -> failwith "Failed to allocate memory in subject_alt_names()"
    | Some results_p_p ->
      protect
        ~f:(fun () ->
          let rec loop acc p =
            match !@p with
            | None -> List.rev acc
            | Some san ->
              (match coerce (ptr char) string_opt san with
               | None -> failwith "Coercion of subjectAltName string failed"
               | Some s -> loop (s :: acc) (p +@ 1))
          in
          loop [] results_p_p)
        ~finally:(fun () -> Bindings.X509.free_subject_alt_names results_p_p)
  ;;

  let fingerprint t algo =
    let open Ctypes in
    let buf = allocate_n char ~count:Types.Evp.max_md_size in
    let len = allocate int 0 in
    let algo =
      match algo with
      | `SHA1 -> Bindings.EVP.sha1 ()
    in
    if Bindings.X509.digest t algo buf len
    then Ctypes.string_from_ptr buf ~length:!@len
    else raise_s [%message "Failed to compute digest"]
  ;;

  let check_host t name =
    (* see https://www.openssl.org/docs/manmaster/man3/X509_check_host.html *)
    let flags = 0 in
    let status = Bindings.X509.check_host t name (String.length name) flags None in
    if status = 1
    then Ok ()
    else if status = 0
    then Or_error.error_s [%message "hostname did not match"]
    else if status = -1
    then Or_error.error_s [%message "open_ssl internal error"]
    else if status = -2
    then Or_error.error_s [%message "malformed certificate"]
    else
      Or_error.error_s
        [%message "Unexpected status code from X509_check_host" (status : int)]
  ;;

  let check_ip t name =
    (* see https://www.openssl.org/docs/manmaster/man3/X509_check_host.html *)
    let flags = 0 in
    let status = Bindings.X509.check_ip t name flags in
    if status = 1
    then Ok ()
    else if status = 0
    then Or_error.error_s [%message "ip did not match"]
    else if status = -1
    then Or_error.error_s [%message "open_ssl internal error"]
    else if status = -2
    then
      Or_error.error_s
        [%message
          [%string
            "malformed input to check_ip. Expected if %{name} isn't an IP address."]]
    else
      Or_error.error_s
        [%message "Unexpected status code from X509_check_ip_asc" (status : int)]
  ;;
end

module Ssl_session = struct
  type t = Bindings.Ssl_session.t

  let create_exn () =
    match Bindings.Ssl_session.new_ () with
    | Some p ->
      Gc.add_finalizer_exn p Bindings.Ssl_session.free;
      p
    | None -> failwith "Unable to allocate an SSL session."
  ;;
end

module Bignum = struct
  type t = Bindings.Bignum.t

  let create_no_gc (`hex hex) =
    let p_ref = Ctypes.(allocate Bindings.Bignum.t_opt None) in
    let _len = Bindings.Bignum.hex2bn p_ref hex in
    match Ctypes.( !@ ) p_ref with
    | Some p -> p
    | None -> failwith "Unable to allocate/init Bignum."
  ;;
end

module Dh = struct
  type t = Bindings.Dh.t

  let create ~prime ~generator : t =
    match Bindings.Dh.new_ () with
    | None -> failwith "Unable to allocate/generate DH parameters."
    | Some p ->
      Gc.add_finalizer_exn p Bindings.Dh.free;
      let p_struct =
        Ctypes.( !@ ) Ctypes.(coerce Bindings.Dh.t (ptr Bindings.Dh.Struct.t) p)
      in
      Ctypes.setf p_struct Bindings.Dh.Struct.p (Bignum.create_no_gc prime);
      Ctypes.setf p_struct Bindings.Dh.Struct.g (Bignum.create_no_gc generator);
      p
  ;;

  let generate_parameters ~prime_len ~generator () : t =
    match Bindings.Dh.generate_parameters prime_len generator None Ctypes.null with
    | None -> failwith "Unable to allocate/generate DH parameters."
    | Some p ->
      Gc.add_finalizer_exn p Bindings.Dh.free;
      p
  ;;
end

module Ssl = struct
  type t = Bindings.Ssl.t [@@deriving sexp_of]

  (* for use in ctypes signatures *)

  let create_exn ctx =
    match Bindings.Ssl.new_ ctx with
    | None -> failwith "Unable to allocate an SSL connection."
    | Some p ->
      Gc.add_finalizer_exn p Bindings.Ssl.free;
      p
  ;;

  let set_method t version =
    let version_method =
      let open Version in
      match version with
      | Sslv23 -> Ssl_method.sslv23 ()
      | Tls -> Ssl_method.tls ()
      | Sslv3 -> Ssl_method.sslv3 ()
      | Tlsv1 -> Ssl_method.tlsv1 ()
      | Tlsv1_1 -> Ssl_method.tlsv1_1 ()
      | Tlsv1_2 -> Ssl_method.tlsv1_2 ()
      | Tlsv1_3 -> Ssl_method.tlsv1_3 ()
    in
    match Bindings.Ssl.set_method t version_method with
    | 1 -> ()
    | e -> failwithf "Failed to set SSL version: %i" e ()
  ;;

  let get_connect_accept_error ssl ~retval =
    if retval = 1
    then Ok ()
    else if retval <= 0
    then (
      let error = Bindings.Ssl.get_error ssl retval in
      match Ssl_error.of_int error with
      | Ok () ->
        failwithf
          "OpenSSL bug: SSL_connect or SSL_accept returned %d, but get_error returned \
           SSL_ERROR_NONE"
          retval
          ()
      | Error error -> Error error)
    else failwithf "OpenSSL bug: get_error returned %d, should be <= 1" retval ()
  ;;

  let get_read_write_error ssl ~retval =
    if retval > 0
    then Ok retval
    else (
      let error = Bindings.Ssl.get_error ssl retval in
      match Ssl_error.of_int error with
      | Ok () ->
        failwithf
          "OpenSSL bug: SSL_read or SSL_write returned %d, but get_error returned \
           SSL_ERROR_NONE"
          retval
          ()
      | Error error -> Error error)
  ;;

  let set_initial_state ssl = function
    | `Connect -> Bindings.Ssl.set_connect_state ssl
    | `Accept -> Bindings.Ssl.set_accept_state ssl
  ;;

  let connect ssl =
    let open Result.Let_syntax in
    let retval = Bindings.Ssl.connect ssl in
    let%bind () = get_connect_accept_error ssl ~retval in
    if verbose then Debug.amf [%here] "SSL_connect -> %i" retval;
    return ()
  ;;

  let accept ssl =
    let open Result.Let_syntax in
    let retval = Bindings.Ssl.accept ssl in
    let%bind () = get_connect_accept_error ssl ~retval in
    if verbose then Debug.amf [%here] "SSL_accept -> %i" retval;
    return ()
  ;;

  let set_bio ssl ~input ~output = Bindings.Ssl.set_bio ssl input output

  let read ssl ~buf ~len =
    let retval = Bindings.Ssl.read ssl buf len in
    if verbose then Debug.amf [%here] "SSL_read(%i) -> %i" len retval;
    get_read_write_error ssl ~retval
  ;;

  let write ssl ~buf ~len =
    let retval = Bindings.Ssl.write ssl buf len in
    if verbose then Debug.amf [%here] "SSL_write(%i) -> %i" len retval;
    get_read_write_error ssl ~retval
  ;;

  let set_verify t flags =
    let mode = List.map flags ~f:Verify_mode.to_int |> List.fold ~init:0 ~f:Int.bit_or in
    Bindings.Ssl.set_verify t mode Ctypes.null
  ;;

  let get_peer_certificate t =
    let cert = Bindings.Ssl.get_peer_certificate t in
    Option.iter cert ~f:(fun cert -> Gc.add_finalizer_exn cert Bindings.X509.free);
    cert
  ;;

  let get_peer_certificate_fingerprint t algo =
    Option.map (Bindings.Ssl.get_peer_certificate t) ~f:(fun cert ->
      protect
        ~f:(fun () -> X509.fingerprint cert algo)
        ~finally:(fun () -> Bindings.X509.free cert))
  ;;

  let check_peer_certificate_host t name =
    match Bindings.Ssl.get_peer_certificate t with
    | None -> Or_error.error_s [%message "No Peer Certificate"]
    | Some cert ->
      protect
        ~f:(fun () ->
          match X509.check_host cert name with
          | Ok () -> Ok ()
          | Error hostname_error ->
            (match X509.check_ip cert name with
             | Ok () -> Ok ()
             (* We prefer returning [hostname_error] and drop error output from [check_ip]
                to avoid introducing more confusing output. *)
             | Error (_ : Error.t) -> Error hostname_error))
        ~finally:(fun () -> Bindings.X509.free cert)
  ;;

  let get_verify_result t =
    let result = Bindings.Ssl.get_verify_result t in
    if result = Types.Verify_result.ok
    then Ok ()
    else
      Option.value
        (Bindings.X509.verify_cert_error_string result)
        ~default:
          (sprintf "unknown verification error (%s)" (Signed.Long.to_string result))
      |> Or_error.error_string
  ;;

  let get_version t =
    let open Version in
    match Bindings.Ssl.get_version t with
    | "SSLv3" -> Sslv3
    | "TLSv1" -> Tlsv1
    | "TLSv1.1" -> Tlsv1_1
    | "TLSv1.2" -> Tlsv1_2
    | "TLSv1.3" -> Tlsv1_3
    | "unknown" ->
      failwith "SSL_get_version returned 'unknown', your session is not established"
    | s -> failwithf "bug: SSL_get_version returned %s" s ()
  ;;

  let session_reused t =
    match Bindings.Ssl.session_reused t with
    | 0 -> false
    | 1 -> true
    | n -> failwithf "OpenSSL bug: SSL_session_reused returned %d" n ()
  ;;

  let set_session t sess =
    match Bindings.Ssl.set_session t sess with
    | 1 -> Ok ()
    | 0 ->
      Or_error.error "SSL_set_session error" (get_error_stack ()) [%sexp_of: string list]
    | n -> failwithf "OpenSSL bug: SSL_set_session returned %d" n ()
  ;;

  let get1_session t =
    let sess = Bindings.Ssl.get1_session t in
    Option.iter sess ~f:(fun sess ->
      (* get1_session increments the reference count *)
      Gc.add_finalizer_exn sess Bindings.Ssl_session.free);
    sess
  ;;

  let check_private_key t =
    match Bindings.Ssl.check_private_key t with
    | 1 -> Ok ()
    | _ ->
      Or_error.error
        "SSL_check_private_key error"
        (get_error_stack ())
        [%sexp_of: string list]
  ;;

  let set_tlsext_host_name context hostname =
    let hostname = Ctypes.(coerce string (ptr char)) hostname in
    match Bindings.Ssl.set_tlsext_host_name context hostname with
    | 1 -> Ok ()
    | 0 ->
      Or_error.error
        "SSL_set_tlsext_host_name error"
        (get_error_stack ())
        [%sexp_of: string list]
    | n -> failwithf "OpenSSL bug: SSL_set_tlsext_host_name returned %d" n ()
  ;;

  let set_cipher_list_exn t ciphers =
    match Bindings.Ssl.set_cipher_list t (String.concat ~sep:":" ("-ALL" :: ciphers)) with
    | 1 -> ()
    | 0 ->
      failwithf !"SSL_set_cipher_list error: %{sexp:string list}" (get_error_stack ()) ()
    | n -> failwithf "OpenSSL bug: SSL_set_cipher_list returned %d" n ()
  ;;

  let set1_groups_list_exn t groups =
    match Bindings.Ssl.set1_groups_list t (String.concat ~sep:":" groups) with
    | 1 -> ()
    | 0 ->
      failwithf !"SSL_set1_groups_list error: %{sexp:string list}" (get_error_stack ()) ()
    | n -> failwithf "OpenSSL bug: SSL_set1_groups_list returned %d" n ()
  ;;

  let get_cipher_list t =
    let rec loop i acc =
      match Bindings.Ssl.get_cipher_list t i with
      | Some c -> loop (i + 1) (c :: acc)
      | None -> List.rev acc
    in
    loop 0 []
  ;;

  let get_peer_certificate_chain t =
    let open Ctypes in
    match Bindings.Ssl.pem_peer_certificate_chain t with
    | None -> None
    | Some results_p ->
      protect
        ~f:(fun () ->
          match coerce (ptr char) string_opt results_p with
          | None -> failwith "Coercion of certificate chain failed"
          | Some s -> Some s)
        ~finally:(fun () -> Bindings.Ssl.free_pem_peer_certificate_chain results_p)
  ;;

  let get_alpn_selected t =
    let open Ctypes in
    let protocol = allocate (ptr char) (coerce (ptr void) (ptr char) null) in
    let len = allocate int 0 in
    Bindings.Ssl.get_alpn_selected t protocol len;
    if is_null !@protocol
    then None
    else String.init !@len ~f:(fun pos -> !@(!@protocol +@ pos)) |> Some
  ;;
end
