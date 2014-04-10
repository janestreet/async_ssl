open Core.Std
open Async.Std
open Import

module Bindings = Ffi_bindings

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
        | V.Sslv23 -> Bindings.sslv23_method ()
      in
      match Bindings.Ssl_ctx.ssl_ctx_new ver_method with
      | None   -> failwith "Could not allocate a new SSL context."
      | Some p ->
        Gc.add_finalizer_exn p Bindings.Ssl_ctx.ssl_ctx_free;
        p
  ;;

  let load_verify_locations =
    fun ?ca_file ?ca_path ctx ->
      In_thread.run (fun () -> Bindings.Ssl_ctx.ssl_ctx_load_verify_locations ctx ca_file ca_path)
      >>= function
      | 0 -> Deferred.return (Or_error.return ())
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
      Bindings.Bio.bio_s_mem ()
      |> Bindings.Bio.bio_new
  ;;

  let read =
    fun bio ~buf ~len ->
      let retval = Bindings.Bio.bio_read bio buf len in
      if verbose then Debug.amf _here_ "BIO_read(%i) -> %i" len retval;
      retval
  ;;

  let write =
    fun bio ~buf ~len ->
      let retval = Bindings.Bio.bio_write bio buf len in
      if verbose then Debug.amf _here_ "BIO_write(%i) -> %i" len retval;
      retval
  ;;
end

module Ssl = struct

  type t = unit Ctypes.ptr

  let t = Ctypes.(ptr void) (* for use in ctypes signatures *)

  let sexp_of_t ssl = Ctypes.(ptr_diff ssl null) |> <:sexp_of<int>>

  let create_exn =
    fun ctx ->
      let p = Bindings.Ssl.ssl_new ctx in
      if p = Ctypes.null
      then failwith "Unable to allocate an SSL connection."
      else begin
      Gc.add_finalizer_exn p Bindings.Ssl.ssl_free;
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
        | Sslv23 -> Bindings.sslv23_method ()
      in
      match Bindings.Ssl.ssl_set_method t version_method with
      | 1 -> ()
      | e -> failwithf "Failed to set SSL version: %i" e ()
  ;;

  let get_error =
    let module E = Ssl_error in
    fun ssl ~retval ->
      Bindings.Ssl.ssl_get_error ssl retval
      |> function
      | 1 -> Error E.Ssl_error
      | 2 -> Error E.Want_read
      | 3 -> Error E.Want_write
      | 4 -> Error E.Want_X509_lookup
      | 5 -> Error E.Syscall_error
      | 6 -> Error E.Zero_return
      | 7 -> Error E.Want_connect
      | 8 -> Error E.Want_accept
      | _ -> Ok    retval
  ;;

  let set_initial_state =
    fun ssl -> function
      | `Connect -> Bindings.Ssl.ssl_set_connect_state ssl
      | `Accept  -> Bindings.Ssl.ssl_set_accept_state ssl
  ;;

  let connect =
    fun ssl ->
      let retval = Bindings.Ssl.ssl_connect ssl in
      Result.(get_error ssl ~retval
              >>= fun _ ->
              if verbose then Debug.amf _here_ "SSL_connect -> %i" retval;
              return ())
  ;;

  let accept =
    fun ssl ->
      let retval = Bindings.Ssl.ssl_accept ssl in
      Result.(get_error ssl ~retval
              >>= fun _ ->
              if verbose then Debug.amf _here_ "SSL_accept -> %i" retval;
              return ())

  let set_bio =
    fun ssl ~input ~output ->
      Bindings.Ssl.ssl_set_bio ssl input output
  ;;

  let read =
    fun ssl ~buf ~len ->
      let retval = Bindings.Ssl.ssl_read ssl buf len in
      if verbose then Debug.amf _here_ "SSL_read(%i) -> %i" len retval;
      get_error ssl ~retval
  ;;

  let write =
    fun ssl ~buf ~len ->
      let retval = Bindings.Ssl.ssl_write ssl buf len in
      if verbose then Debug.amf _here_ "SSL_write(%i) -> %i" len retval;
      get_error ssl ~retval
  ;;

  let type_to_c_enum = function
    | `PEM  -> 1
    | `ASN1 -> 2
  ;;

  let use_certificate_file =
    fun ssl ~crt ~file_type ->
      let c_enum = type_to_c_enum file_type in
      In_thread.run (fun () ->
        let retval = Bindings.Ssl.ssl_use_certificate_file ssl crt c_enum in
        if retval > 0
        then Ok ()
        else Error (get_error_stack ()))
  ;;

  let use_private_key_file =
    fun ssl ~key ~file_type ->
      let c_enum = type_to_c_enum file_type in
      In_thread.run (fun () ->
        let retval = Bindings.Ssl.ssl_use_private_key_file ssl key c_enum in
        if retval > 0
        then Ok ()
        else Error (get_error_stack ()))
  ;;
end
