open Core.Std
open Async.Std
open Import

let foreign = Foreign.foreign

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
  let err_get_error =
    foreign "ERR_get_error" Ctypes.(void @-> returning ulong)
  in
  let err_error_string_n =
    foreign "ERR_error_string_n" Ctypes.(ulong @-> ptr char @-> int @-> returning void)
  in
  let err_error_string =
    (* We need to write error strings from C into bigstrings.  To reduce allocation, reuse
       scratch space for this. *)
    let scratch_space = Bigstring.create 1024 in
    fun err ->
      err_error_string_n
        err
        (Ctypes.bigarray_start Ctypes.array1 scratch_space)
        (Bigstring.length scratch_space);
      Bigstring.to_string ~len:(bigstring_strlen scratch_space) scratch_space
  in
  fun () ->
    iter_while_rev
      ~iter:err_get_error
      ~cond:(fun x -> x <> Unsigned.ULong.zero)
    |> List.rev_map ~f:err_error_string
;;

(* In reality, this function returns an int... that's always 1. That's silly. *)

(* OpenSSL_add_all_algorithms is a macro, so we have to replicate it manually. :( *)
let add_all_algorithms =
  let add_all_digests =
    foreign "OpenSSL_add_all_digests" Ctypes.(void @-> returning void)
  in
  let add_all_ciphers =
    foreign "OpenSSL_add_all_ciphers" Ctypes.(void @-> returning void)
  in
  fun () ->
    add_all_ciphers ();
    add_all_digests ();
;;

(* Call the openssl initialization method if it hasn't been already. *)
(* val possibly_init : unit -> unit *)
let possibly_init =
  let init = foreign "SSL_library_init" Ctypes.(void @-> returning ulong) in
  let ssl_load_error_strings =
    foreign "SSL_load_error_strings" Ctypes.(void @-> returning void)
  in
  let initialized = ref false in
  fun () ->
    if not !initialized then begin
      initialized := true;
      (* SSL_library_init() always returns "1", so it is safe to discard the return
         value. *)
      ignore (init () : Unsigned.ulong);
      ssl_load_error_strings ();
      add_all_algorithms ();
    end
;;

let ssl_method_t  = Ctypes.(void @-> returning (ptr void))
let sslv3_method  = foreign "SSLv3_method"  ssl_method_t
let tlsv1_method  = foreign "TLSv1_method"  ssl_method_t
let sslv23_method = foreign "SSLv23_method" ssl_method_t

module Ssl_ctx = struct

  type t = unit Ctypes.ptr

  let t = Ctypes.(ptr void) (* for use in ctypes type signatures *)

  let sexp_of_t x = Ctypes.(ptr_diff x null) |> <:sexp_of<int>>

  let create_exn =
    (* SSLv2 isn't secure, so we don't use it.  If you really really really need it, use
       SSLv23 which will at least try to upgrade the security whenever possible.

       let sslv2_method  = foreign "SSLv2_method"  ssl_method_t
    *)
    let ssl_ctx_new =
      foreign "SSL_CTX_new" Ctypes.(ptr void @-> returning (ptr_opt void))
    in
    let ssl_ctx_free =
      foreign "SSL_CTX_free" Ctypes.(t @-> returning void)
    in
    fun ver ->
      possibly_init ();
      let ver_method =
        let module V = Version in
        match ver with
        | V.Sslv3  -> sslv3_method  ()
        | V.Tlsv1  -> tlsv1_method  ()
        | V.Sslv23 -> sslv23_method ()
      in
      match ssl_ctx_new ver_method with
      | None   -> failwith "Could not allocate a new SSL context."
      | Some p ->
        Gc.add_finalizer_exn p ssl_ctx_free;
        p
  ;;

  let load_verify_locations =
    let ssl_ctx_load_verify_locations =
      foreign "SSL_CTX_load_verify_locations"
        Ctypes.(t @-> string_opt @-> string_opt @-> returning int)
    in
    fun ?ca_file ?ca_path ctx ->
      In_thread.run (fun () -> ssl_ctx_load_verify_locations ctx ca_file ca_path)
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
    let bio_new =
      foreign "BIO_new" Ctypes.(ptr void @-> returning t)
    in
    let bio_s_mem =
      foreign "BIO_s_mem" Ctypes.(void @-> returning (ptr void))
    in
    fun () ->
      bio_s_mem ()
      |> bio_new
  ;;

  let read =
    let bio_read =
      foreign "BIO_read" Ctypes.(t @-> ptr char @-> int @-> returning int)
    in
    fun bio ~buf ~len ->
      let retval = bio_read bio buf len in
      if verbose then Debug.amf _here_ "BIO_read(%i) -> %i" len retval;
      retval
  ;;

  let write =
    let bio_write =
      foreign "BIO_write" Ctypes.(t @-> string @-> int @-> returning int)
    in
    fun bio ~buf ~len ->
      let retval = bio_write bio buf len in
      if verbose then Debug.amf _here_ "BIO_write(%i) -> %i" len retval;
      retval
  ;;
end

module Ssl = struct

  type t = unit Ctypes.ptr

  let t = Ctypes.(ptr void) (* for use in ctypes signatures *)

  let sexp_of_t ssl = Ctypes.(ptr_diff ssl null) |> <:sexp_of<int>>

  let create_exn =
    let ssl_new  = foreign "SSL_new"  Ctypes.(Ssl_ctx.t @-> returning t)    in
    let ssl_free = foreign "SSL_free" Ctypes.(        t @-> returning void) in
    fun ctx ->
      let p = ssl_new ctx in
      if p = Ctypes.null
      then failwith "Unable to allocate an SSL connection."
      else begin
      Gc.add_finalizer_exn p ssl_free;
      p
      end
  ;;

  let set_method =
    let ssl_set_method =
      foreign "SSL_set_ssl_method" Ctypes.(t @-> ptr void @-> returning int)
    in
    fun t version ->
      let version_method =
        let open Version in
        match version with
        | Sslv3  -> sslv3_method ()
        | Tlsv1  -> tlsv1_method ()
        | Sslv23 -> sslv23_method ()
      in
      match ssl_set_method t version_method with
      | 1 -> ()
      | e -> failwithf "Failed to set SSL version: %i" e ()
  ;;

  let get_error =
    let ssl_get_error =
      foreign "SSL_get_error" Ctypes.(ptr void @-> int @-> returning int)
    in
    let module E = Ssl_error in
    fun ssl ~retval ->
      ssl_get_error ssl retval
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
    let ssl_set_connect_state =
      foreign "SSL_set_connect_state" Ctypes.(t @-> returning void)
    in
    let ssl_set_accept_state =
      foreign "SSL_set_accept_state" Ctypes.(t @-> returning void)
    in
    fun ssl -> function
      | `Connect -> ssl_set_connect_state ssl
      | `Accept  -> ssl_set_accept_state ssl
  ;;

  let connect =
    let ssl_connect = foreign "SSL_connect" Ctypes.(t @-> returning int) in
    fun ssl ->
      let retval = ssl_connect ssl in
      Result.(get_error ssl ~retval
              >>= fun _ ->
              if verbose then Debug.amf _here_ "SSL_connect -> %i" retval;
              return ())
  ;;

  let accept =
    let ssl_accept = foreign "SSL_accept" Ctypes.(t @-> returning int) in
    fun ssl ->
      let retval = ssl_accept ssl in
      Result.(get_error ssl ~retval
              >>= fun _ ->
              if verbose then Debug.amf _here_ "SSL_accept -> %i" retval;
              return ())

  let set_bio =
    let ssl_set_bio =
      foreign "SSL_set_bio" Ctypes.(t @-> Bio.t @-> Bio.t @-> returning void)
    in
    fun ssl ~input ~output ->
      ssl_set_bio ssl input output
  ;;

  let read =
    let ssl_read =
      foreign "SSL_read" Ctypes.(t @-> ptr char @-> int @-> returning int)
    in
    fun ssl ~buf ~len ->
      let retval = ssl_read ssl buf len in
      if verbose then Debug.amf _here_ "SSL_read(%i) -> %i" len retval;
      get_error ssl ~retval
  ;;

  let write =
    let ssl_write =
      foreign "SSL_write" Ctypes.(t @-> string @-> int @-> returning int)
    in
    fun ssl ~buf ~len ->
      let retval = ssl_write ssl buf len in
      if verbose then Debug.amf _here_ "SSL_write(%i) -> %i" len retval;
      get_error ssl ~retval
  ;;

  let type_to_c_enum = function
    | `PEM  -> 1
    | `ASN1 -> 2
  ;;

  let use_certificate_file =
    let ssl_use_certificate_file =
      foreign "SSL_use_certificate_file" Ctypes.(t @-> string @-> int @-> returning int)
    in
    fun ssl ~crt ~file_type ->
      let c_enum = type_to_c_enum file_type in
      In_thread.run (fun () ->
        let retval = ssl_use_certificate_file ssl crt c_enum in
        if retval > 0
        then Ok ()
        else Error (get_error_stack ()))
  ;;

  let use_private_key_file =
    let ssl_use_private_key_file =
      foreign "SSL_use_PrivateKey_file" Ctypes.(t @-> string @-> int @-> returning int)
    in
    fun ssl ~key ~file_type ->
      let c_enum = type_to_c_enum file_type in
      In_thread.run (fun () ->
        let retval = ssl_use_private_key_file ssl key c_enum in
        if retval > 0
        then Ok ()
        else Error (get_error_stack ()))
  ;;
end
