let foreign = Foreign.foreign

let err_get_error = foreign "ERR_get_error"
  Ctypes.(void @-> returning ulong)

let err_error_string_n = foreign "ERR_error_string_n"
  Ctypes.(ulong @-> ptr char @-> int @-> returning void)

let add_all_digests = foreign "OpenSSL_add_all_digests"
  Ctypes.(void @-> returning void)

let add_all_ciphers = foreign "OpenSSL_add_all_ciphers"
  Ctypes.(void @-> returning void)

let init = foreign "SSL_library_init"
  Ctypes.(void @-> returning ulong)

let ssl_load_error_strings = foreign "SSL_load_error_strings"
  Ctypes.(void @-> returning void)

let ssl_method_t  = Ctypes.(void @-> returning (ptr void))
let sslv3_method  = foreign "SSLv3_method" ssl_method_t
let tlsv1_method  = foreign "TLSv1_method"  ssl_method_t
let sslv23_method = foreign "SSLv23_method" ssl_method_t
(* SSLv2 isn't secure, so we don't use it.  If you really really really need it, use
   SSLv23 which will at least try to upgrade the security whenever possible.

   let sslv2_method  = foreign "SSLv2_method"  ssl_method_t
*)


module Ssl_ctx =
struct
  let t = Ctypes.(ptr void)

  let ssl_ctx_new = foreign "SSL_CTX_new"
    Ctypes.(ptr void @-> returning (ptr_opt void))

  let ssl_ctx_free = foreign "SSL_CTX_free"
    Ctypes.(t @-> returning void)

  let ssl_ctx_load_verify_locations = foreign "SSL_CTX_load_verify_locations"
    Ctypes.(t @-> string_opt @-> string_opt @-> returning int)
end

module Bio =
struct
  let t = Ctypes.(ptr void) (* for use in ctypes signatures *)

  let bio_new = foreign "BIO_new"
    Ctypes.(ptr void @-> returning t)

  let bio_s_mem = foreign "BIO_s_mem"
    Ctypes.(void @-> returning (ptr void))

  let bio_read = foreign "BIO_read"
    Ctypes.(t @-> ptr char @-> int @-> returning int)

  let bio_write = foreign "BIO_write"
    Ctypes.(t @-> string @-> int @-> returning int)
end

module Ssl =
struct
  let t = Ctypes.(ptr void)

  let ssl_new = foreign "SSL_new"
    Ctypes.(Ssl_ctx.t @-> returning t)

  let ssl_free = foreign "SSL_free"
    Ctypes.(t @-> returning void)

  let ssl_set_method = foreign "SSL_set_ssl_method"
    Ctypes.(t @-> ptr void @-> returning int)

  let ssl_get_error = foreign "SSL_get_error"
    Ctypes.(ptr void @-> int @-> returning int)

  let ssl_set_connect_state = foreign "SSL_set_connect_state"
    Ctypes.(t @-> returning void)

  let ssl_set_accept_state = foreign "SSL_set_accept_state"
    Ctypes.(t @-> returning void)

  let ssl_connect = foreign "SSL_connect"
    Ctypes.(t @-> returning int)

  let ssl_accept = foreign "SSL_accept"
    Ctypes.(t @-> returning int)

  let ssl_set_bio = foreign "SSL_set_bio"
    Ctypes.(t @-> Bio.t @-> Bio.t @-> returning void)

  let ssl_read = foreign "SSL_read"
    Ctypes.(t @-> ptr char @-> int @-> returning int)

  let ssl_write = foreign "SSL_write"
    Ctypes.(t @-> string @-> int @-> returning int)

  let ssl_use_certificate_file = foreign "SSL_use_certificate_file"
    Ctypes.(t @-> string @-> int @-> returning int)

  let ssl_use_private_key_file = foreign "SSL_use_PrivateKey_file"
    Ctypes.(t @-> string @-> int @-> returning int)
end
