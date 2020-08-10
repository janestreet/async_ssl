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
    (* We need to write error strings from C into bigstrings.  To reduce allocation, reuse
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
    in
    match Bindings.Ssl_ctx.new_ ver_method with
    | None -> failwith "Could not allocate a new SSL context."
    | Some p ->
      Gc.add_finalizer_exn p Bindings.Ssl_ctx.free;
      p
  ;;

  let set_options context options =
    let opts =
      List.fold options ~init:Unsigned.ULong.zero ~f:(fun acc opt ->
        let module O = Opt in
        let o =
          match opt with
          | O.No_sslv2 -> Types.Ssl_op.no_sslv2
          | O.No_sslv3 -> Types.Ssl_op.no_sslv3
          | O.No_tlsv1 -> Types.Ssl_op.no_tlsv1
          | O.No_tlsv1_1 -> Types.Ssl_op.no_tlsv1_1
          | O.No_tlsv1_2 -> Types.Ssl_op.no_tlsv1_2
        in
        Unsigned.ULong.logor acc o)
    in
    (* SSL_CTX_set_options(3) returns the new options bitmask after adding options.  We
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
        ~here:[%here]
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
         | _ -> Or_error.error "CA load error" (get_error_stack ()) [%sexp_of: string list])
  ;;

  let set_default_verify_paths ctx =
    match Bindings.Ssl_ctx.set_default_verify_paths ctx with
    | 1 -> ()
    | x ->
      failwiths
        ~here:[%here]
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
    let error i =
      Deferred.Or_error.error
        "Could not set default verify paths."
        (`Return_value i, `Errors (get_error_stack ()))
        [%sexp_of: [ `Return_value of int ] * [ `Errors of string list ]]
    in
    match%bind
      In_thread.run (fun () -> try_certificate_chain_and_failover_to_asn1 ctx crt_file)
    with
    | 1 ->
      (match%bind In_thread.run (fun () -> try_both_private_key_formats ctx key_file) with
       | 1 -> Deferred.Or_error.return ()
       | x -> error x)
    | x -> error x
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

module Ec_key = struct
  type t = Bindings.Ec_key.t

  module Curve = struct
    module T = struct
      type t = int

      let of_string = Bindings.ASN1_object.txt2nid

      let to_string t =
        match Bindings.ASN1_object.nid2sn t with
        | None -> Int.to_string t
        | Some s -> s
      ;;
    end

    include T
    include Sexpable.Of_stringable (T)

    let secp384r1 = of_string "secp384r1"
    let secp521r1 = of_string "secp521r1"
    let prime256v1 = of_string "prime256v1"
  end

  let new_by_curve_name curve : t =
    match Bindings.Ec_key.new_by_curve_name curve with
    | None -> failwith "Unable to allocate/generate EC key."
    | Some p ->
      Gc.add_finalizer_exn p Bindings.Ec_key.free;
      p
  ;;
end

module Rsa = struct
  type t = Bindings.Rsa.t

  let generate_key ~key_length ~exponent () : t =
    match Bindings.Rsa.generate_key key_length exponent None Ctypes.null with
    | None -> failwith "Unable to allocate/generate RSA key pair."
    | Some p ->
      Gc.add_finalizer_exn p Bindings.Rsa.free;
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
    in
    match Bindings.Ssl.set_method t version_method with
    | 1 -> ()
    | e -> failwithf "Failed to set SSL version: %i" e ()
  ;;

  let get_connect_accept_error ssl ~retval =
    let module E = Ssl_error in
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
    let module E = Ssl_error in
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

  module Tmp_dh_callback = Bindings.Ssl.Tmp_dh_callback

  let set_tmp_dh_callback = Bindings.Ssl.set_tmp_dh_callback
  let set_tmp_ecdh = Bindings.Ssl.set_tmp_ecdh

  module Tmp_rsa_callback = Bindings.Ssl.Tmp_rsa_callback

  let set_tmp_rsa_callback = Bindings.Ssl.set_tmp_rsa_callback

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
end
