open! Core
open Import

let initialized = Set_once.create ()

(* OpenSSL_add_all_algorithms is a macro, so we have to replicate it manually. :( *)
let add_all_algorithms () =
  Bindings.add_all_ciphers ();
  Bindings.add_all_digests ()
;;

(* openssl initialization method, run during module initialization. Hopefully
   before anything uses OpenSSL. *)
let initialize () =
  match Set_once.get initialized with
  | Some () -> ()
  | None ->
    Set_once.set_exn initialized [%here] ();
    (* Static initialization *)
    Bindings.ssl_load_error_strings ();
    Bindings.err_load_crypto_strings ();
    (* Use /etc/ssl/openssl.conf or similar *)
    Bindings.openssl_config None;
    (* Make hardware accelaration available *)
    Bindings.Engine.load_builtin_engines ();
    (* But unload RAND because RDRAND is suspected to have been compromised *)
    Bindings.Engine.unregister_RAND ();
    (* Finish engine registration *)
    Bindings.Engine.register_all_complete ();
    (* SSL_library_init() initializes the SSL algorithms.
       It always returns "1", so it is safe to discard the return value *)
    ignore (Bindings.init () : Unsigned.ulong);
    (* Load any other algorithms, just in case *)
    add_all_algorithms ()
;;
