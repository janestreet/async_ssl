open Core.Std
open Async.Std
open Import

module Types = Async_ssl_bindings.Ffi_bindings.Types(Ffi_generated_types)
module Bindings = Async_ssl_bindings.Ffi_bindings.Bindings(Ffi_generated)

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
  with sexp_of

  let of_int n =
    let open Types.Ssl_error in
    if n = none then Ok ()
    else if n = zero_return then Error Zero_return
    else if n = want_read then Error Want_read
    else if n = want_write then Error Want_write
    else if n = want_connect then Error Want_connect
    else if n = want_accept then Error Want_accept
    else if n = want_x509_lookup then Error Want_X509_lookup
    else if n = syscall then Error Syscall_error
    else if n = ssl then Error Ssl_error
    else failwithf "Unrecognized result of SSL_get_error: %d" n ()
end

module Verify_mode = struct
  type t =
    | Verify_none
    | Verify_peer
    | Verify_fail_if_no_peer_cert
    | Verify_client_once
  with sexp_of

  let to_int t =
    let open Types.Verify_mode in
    match t with
    | Verify_none -> verify_none
    | Verify_peer -> verify_peer
    | Verify_fail_if_no_peer_cert -> verify_fail_if_no_peer_cert
    | Verify_client_once -> verify_client_once
end

let bigstring_strlen bigstr =
  let len = Bigstring.length bigstr in
  let idx = ref 0 in
  while !idx < len && bigstr.{!idx} <> '\x00' do
    incr idx;
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
    iter_while_rev
      ~iter:Bindings.err_get_error
      ~cond:(fun x -> x <> Unsigned.ULong.zero)
    |> List.rev_map ~f:err_error_string
;;

(* In reality, this function returns an int... that's always 1. That's silly. *)

(* OpenSSL_add_all_algorithms is a macro, so we have to replicate it manually. :( *)
let add_all_algorithms =
  fun () ->
    Bindings.add_all_ciphers ();
    Bindings.add_all_digests ();
;;

(* Call the openssl initialization method if it hasn't been already. *)
(* val possibly_init : unit -> unit *)
let possibly_init =
  let initialized = ref false in
  fun () ->
    if not !initialized then begin
      initialized := true;
      (* SSL_library_init() always returns "1", so it is safe to discard the return
         value. *)
      ignore (Bindings.init () : Unsigned.ulong);
      Bindings.ssl_load_error_strings ();
      add_all_algorithms ();
    end
;;

module Ssl_ctx = struct
  type t = unit Ctypes.ptr

  let t = Ctypes.(ptr void) (* for use in ctypes type signatures *)

  let sexp_of_t x = Ctypes.(ptr_diff x null) |> <:sexp_of<int>>

  let create_exn =
    fun ver ->
      possibly_init ();
      let ver_method =
        let module V = Version in
        match ver with
        | V.Sslv3  -> Bindings.sslv3_method  ()
        | V.Tlsv1  -> Bindings.tlsv1_method  ()
        | V.Tlsv1_1 -> Bindings.tlsv1_1_method ()
        | V.Tlsv1_2 -> Bindings.tlsv1_2_method ()
        | V.Sslv23 -> Bindings.sslv23_method ()
      in
      match Bindings.Ssl_ctx.new_ ver_method with
      | None   -> failwith "Could not allocate a new SSL context."
      | Some p ->
        Gc.add_finalizer_exn p Bindings.Ssl_ctx.free;
        p
  ;;

  let set_context_session_id =
    fun context id ->
      begin
        let session_id = Ctypes.(coerce string (ptr char)) id in
        match
          Bindings.Ssl_ctx.set_session_id_context context session_id
            (Unsigned.UInt.of_int (String.length id))
        with
        | 1 -> ()
        | x -> failwiths "Could not set session id context."
                 (`Return_value x, `Errors (get_error_stack ()))
                 <:sexp_of<[`Return_value of int] * [`Errors of string list]>>
      end
  ;;

  let load_verify_locations =
    fun ?ca_file ?ca_path ctx ->
      In_thread.run (fun () -> Bindings.Ssl_ctx.load_verify_locations ctx ca_file ca_path)
      >>= function
        (* Yep, 1 means success. *)
      | 1 -> Deferred.return (Or_error.return ())
      | _ -> Deferred.return begin
        match (ca_file, ca_path) with
        | (None, None) -> Or_error.error_string "No CA files given."
        | _ -> Or_error.error "CA load error" (get_error_stack ()) <:sexp_of<string list>>
      end
  ;;
end

module Bio = struct

  type t = unit Ctypes.ptr

  let t = Ctypes.(ptr void) (* for use in ctypes signatures *)

  let sexp_of_t bio = Ctypes.(ptr_diff bio null) |> <:sexp_of<int>>

  let create =
    fun () ->
      Bindings.Bio.s_mem ()
      |> Bindings.Bio.new_
  ;;

  let read =
    fun bio ~buf ~len ->
      let retval = Bindings.Bio.read bio buf len in
      if verbose then Debug.amf _here_ "BIO_read(%i) -> %i" len retval;
      retval
  ;;

  let write =
    fun bio ~buf ~len ->
      let retval = Bindings.Bio.write bio buf len in
      if verbose then Debug.amf _here_ "BIO_write(%i) -> %i" len retval;
      retval
  ;;
end

module ASN1_object = struct
  type t = unit Ctypes.ptr

  let obj2nid = Bindings.ASN1_object.obj2nid
  let nid2sn n =
    Option.value (Bindings.ASN1_object.nid2sn n)
      ~default:(sprintf "unknown object nid (%d)" n)
end

module ASN1_string = struct
  type t = unit Ctypes.ptr

  let data t =
    Bindings.ASN1_string.data t
end

module X509_name_entry = struct
  type t = unit Ctypes.ptr

  let get_object = Bindings.X509_name_entry.get_object
  let get_data = Bindings.X509_name_entry.get_data
end

module X509_name = struct
  type t = unit Ctypes.ptr

  let entry_count = Bindings.X509_name.entry_count
  let get_entry = Bindings.X509_name.get_entry
end

module X509 = struct
  type t = unit Ctypes.ptr

  let get_subject_name t =
    let name = Bindings.X509.get_subject_name t in
    if name = Ctypes.null then failwith "Certificate contains no subject name.";
    name
end

module Ssl_session = struct
  type t = unit Ctypes.ptr

  let create_exn () =
    let p = Bindings.Ssl_session.new_ () in
    if p = Ctypes.null
    then failwith "Unable to allocate an SSL session."
    else begin
      Gc.add_finalizer_exn p Bindings.Ssl_session.free;
      p
    end
  ;;
end

module Ssl = struct

  type t = unit Ctypes.ptr

  let t = Ctypes.(ptr void) (* for use in ctypes signatures *)

  let sexp_of_t ssl = Ctypes.(ptr_diff ssl null) |> <:sexp_of<int>>

  let create_exn =
    fun ctx ->
      let p = Bindings.Ssl.new_ ctx in
      if p = Ctypes.null
      then failwith "Unable to allocate an SSL connection."
      else begin
      Gc.add_finalizer_exn p Bindings.Ssl.free;
      p
      end
  ;;

  let set_method =
    fun t version ->
      let version_method =
        let open Version in
        match version with
        | Sslv3  -> Bindings.sslv3_method ()
        | Tlsv1  -> Bindings.tlsv1_method ()
        | Tlsv1_1 -> Bindings.tlsv1_1_method ()
        | Tlsv1_2 -> Bindings.tlsv1_2_method ()
        | Sslv23 -> Bindings.sslv23_method ()
      in
      match Bindings.Ssl.set_method t version_method with
      | 1 -> ()
      | e -> failwithf "Failed to set SSL version: %i" e ()
  ;;

  let get_connect_accept_error ssl ~retval =
    let module E = Ssl_error in
    if retval = 1 then Ok ()
    else if retval <= 0 then begin
      let error = Bindings.Ssl.get_error ssl retval in
      match Ssl_error.of_int error with
      | Ok () ->
        failwithf
          "OpenSSL bug: SSL_connect or SSL_accept returned %d, but get_error \
           returned SSL_ERROR_NONE" retval ()
      | Error error -> Error error
    end
    else failwithf "OpenSSL bug: get_error returned %d, should be <= 1" retval ()
  ;;

  let get_read_write_error ssl ~retval =
    let module E = Ssl_error in
    if retval > 0 then Ok retval
    else begin
      let error = Bindings.Ssl.get_error ssl retval in
      match Ssl_error.of_int error with
      | Ok () ->
        failwithf
          "OpenSSL bug: SSL_read or SSL_write returned %d, but get_error \
           returned SSL_ERROR_NONE" retval ()
      | Error error -> Error error
    end
  ;;


  let set_initial_state =
    fun ssl -> function
      | `Connect -> Bindings.Ssl.set_connect_state ssl
      | `Accept  -> Bindings.Ssl.set_accept_state ssl
  ;;

  let connect =
    fun ssl ->
      let retval = Bindings.Ssl.connect ssl in
      Result.(get_connect_accept_error ssl ~retval
              >>= fun () ->
              if verbose then Debug.amf _here_ "SSL_connect -> %i" retval;
              return ())
  ;;

  let accept =
    fun ssl ->
      let retval = Bindings.Ssl.accept ssl in
      Result.(get_connect_accept_error ssl ~retval
              >>= fun () ->
              if verbose then Debug.amf _here_ "SSL_accept -> %i" retval;
              return ())

  let set_bio =
    fun ssl ~input ~output ->
      Bindings.Ssl.set_bio ssl input output
  ;;

  let read =
    fun ssl ~buf ~len ->
      let retval = Bindings.Ssl.read ssl buf len in
      if verbose then Debug.amf _here_ "SSL_read(%i) -> %i" len retval;
      get_read_write_error ssl ~retval
  ;;

  let write =
    fun ssl ~buf ~len ->
      let retval = Bindings.Ssl.write ssl buf len in
      if verbose then Debug.amf _here_ "SSL_write(%i) -> %i" len retval;
      get_read_write_error ssl ~retval
  ;;

  let type_to_c_enum = function
    | `PEM  -> 1
    | `ASN1 -> 2
  ;;

  let use_certificate_file =
    fun ssl ~crt ~file_type ->
      let c_enum = type_to_c_enum file_type in
      In_thread.run (fun () ->
        let retval = Bindings.Ssl.use_certificate_file ssl crt c_enum in
        if retval > 0
        then Ok ()
        else Error (get_error_stack ()))
  ;;

  let use_private_key_file =
    fun ssl ~key ~file_type ->
      let c_enum = type_to_c_enum file_type in
      In_thread.run (fun () ->
        let retval = Bindings.Ssl.use_private_key_file ssl key c_enum in
        if retval > 0
        then Ok ()
        else Error (get_error_stack ()))

  let set_verify t flags =
    let mode =
      List.map flags ~f:Verify_mode.to_int
      |> List.fold ~init:0 ~f:Int.bit_or
    in
    Bindings.Ssl.set_verify t mode Ctypes.null
  ;;

  let get_peer_certificate t =
    let cert = Bindings.Ssl.get_peer_certificate t in
    if cert = Ctypes.null then None else Some cert

  let get_verify_result t =
    let result = Bindings.Ssl.get_verify_result t in
    if result = Types.Verify_result.ok then Ok ()
    else begin
      Option.value (Bindings.X509.verify_cert_error_string result)
        ~default:(sprintf "unknown verification error (%s)"
                    (Signed.Long.to_string result))
      |> Or_error.error_string
    end

  let get_version t =
    let open Version in
    match Bindings.Ssl.get_version t with
    | "SSLv3" -> Sslv3
    | "TLSv1" -> Tlsv1
    | "TLSv1.1" -> Tlsv1_1
    | "TLSv1.2" -> Tlsv1_2
    | "unknown" -> failwith "SSL_get_version returned 'unknown', your \
                             session is not established"
    | s -> failwithf "bug: SSL_get_version returned %s" s ()

  let session_reused t =
    match Bindings.Ssl.session_reused t with
    | 0 -> false
    | 1 -> true
    | n -> failwithf "OpenSSL bug: SSL_session_reused returned %d" n ()

  let set_session t sess =
    match Bindings.Ssl.set_session t sess with
    | 1 -> Ok ()
    | 0 -> Or_error.error "SSL_set_session error"
             (get_error_stack ()) <:sexp_of<string list>>
    | n -> failwithf "OpenSSL bug: SSL_set_session returned %d" n ()

  let get1_session t =
    let sess = Bindings.Ssl.get1_session t in
    if Ctypes.(to_voidp sess = null)
    then None
    else begin
      (* get1_session increments the reference count *)
      Gc.add_finalizer_exn sess Bindings.Ssl_session.free;
      Some sess
    end

  let check_private_key t =
    match Bindings.Ssl.check_private_key t with
    | 1 -> Ok ()
    | _ -> Or_error.error "SSL_check_private_key error"
             (get_error_stack ()) <:sexp_of<string list>>
end
