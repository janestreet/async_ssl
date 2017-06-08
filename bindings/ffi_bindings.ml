#import "config.h"

module Types(F : Cstubs.Types.TYPE) =
struct
  module Ssl_op = struct
    let no_sslv2 =
      F.constant "SSL_OP_NO_SSLv2" F.ulong
    let no_sslv3 =
      F.constant "SSL_OP_NO_SSLv3" F.ulong
    let no_tlsv1 =
      F.constant "SSL_OP_NO_TLSv1" F.ulong
    let no_tlsv1_1 =
      F.constant "SSL_OP_NO_TLSv1_1" F.ulong
    let no_tlsv1_2 =
      F.constant "SSL_OP_NO_TLSv1_2" F.ulong
  end

  module Verify_mode = struct
    let verify_none =
      F.constant "SSL_VERIFY_NONE" F.int
    let verify_peer =
      F.constant "SSL_VERIFY_PEER" F.int
    let verify_fail_if_no_peer_cert =
      F.constant "SSL_VERIFY_FAIL_IF_NO_PEER_CERT" F.int
    let verify_client_once =
      F.constant "SSL_VERIFY_CLIENT_ONCE" F.int
  end

  module Verify_result = struct
    (* Other codes should be obtained with X509.verify_cert_error_string *)
    let ok =
      F.constant "X509_V_OK" F.long
  end

  module Ssl_error = struct
    let none =
      F.constant "SSL_ERROR_NONE" F.int
    let zero_return =
      F.constant "SSL_ERROR_ZERO_RETURN" F.int
    let want_read =
      F.constant "SSL_ERROR_WANT_READ" F.int
    let want_write =
      F.constant "SSL_ERROR_WANT_WRITE" F.int
    let want_connect =
      F.constant "SSL_ERROR_WANT_CONNECT" F.int
    let want_accept =
      F.constant "SSL_ERROR_WANT_ACCEPT" F.int
    let want_x509_lookup =
      F.constant "SSL_ERROR_WANT_X509_LOOKUP" F.int
    let syscall =
      F.constant "SSL_ERROR_SYSCALL" F.int
    let ssl =
      F.constant "SSL_ERROR_SSL" F.int
  end
end

module Bindings (F : Cstubs.FOREIGN) =
struct
  let foreign = F.foreign

  module Ctypes = struct
    include Ctypes

    let (@->)         = F.(@->)
    let returning     = F.returning
    let foreign       = F.foreign
    let foreign_value = F.foreign_value
  end

  (* Some systems with older OpenSSL don't support TLS 1.1 and 1.2.
     https://github.com/janestreet/async_ssl/issues/3

     This was originally solved by using [Ctypes_foreign_threaded.Foreign.foreign ~stub:true].
     We now detect available symbols at compile time.

     Bindings are uniformly using stubs (no libffi dependency).

     Note: using [Ctypes_foreign_threaded.Foreign.foreign ~stub:true] was failing (segfault)
     with 32bit build on 64bit host.
  *)
  module Ssl_method = struct
    let ssl_method_t = Ctypes.(void @-> returning (ptr void))
    let dummy name () = failwith (Printf.sprintf "Ssl_method %s not implemented" name)
    let implemented name = foreign name ssl_method_t
    let helper name f = f name

    let sslv3 = helper "SSLv3_method"
#ifdef JSC_SSLv3_method
      implemented
#else
      dummy
#endif

    let tlsv1 = helper "TLSv1_method"
#ifdef JSC_TLSv1_method
      implemented
#else
      dummy
#endif

    let tlsv1_1 = helper "TLSv1_1_method"
#ifdef JSC_TLSv1_1_method
      implemented
#else
      dummy
#endif

    let tlsv1_2 = helper "TLSv1_2_method"
#ifdef JSC_TLSv1_2_method
      implemented
#else
      dummy
#endif

    let sslv23 = helper "SSLv23_method"
#ifdef JSC_SSLv23_method
      implemented
#else
      dummy
#endif

    (* SSLv2 isn't secure, so we don't use it.  If you really really really need it, use
       SSLv23 which will at least try to upgrade the security whenever possible.

       let sslv2_method  = foreign "SSLv2_method"  ssl_method_t
    *)
  end

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

  module Ssl_ctx =
  struct
    let t = Ctypes.(ptr void)

    (* free with SSL_CTX_free() (source: manpage of SSL_CTX_free(3)) *)
    let new_ = foreign "SSL_CTX_new"
      Ctypes.(ptr void @-> returning (ptr_opt void))

    let free = foreign "SSL_CTX_free"
      Ctypes.(t @-> returning void)

    let load_verify_locations = foreign "SSL_CTX_load_verify_locations"
      Ctypes.(t @-> string_opt @-> string_opt @-> returning int)

    let set_session_id_context = foreign "SSL_CTX_set_session_id_context"
      Ctypes.(t @-> ptr char @-> uint @-> returning int)

    let set_options = foreign "SSL_CTX_set_options"
      Ctypes.(t @-> ulong @-> returning ulong)
  end

  module Bio =
  struct
    let t = Ctypes.(ptr void) (* for use in ctypes signatures *)

    (* Returns a [BIO *] that is later assigned to an [SSL] object by calling
       SSL_set_bio(3).  The [BIO *] is freed automatically when calling SSL_free().
       (source: manpage of SSL_free(3)) *)
    let new_ = foreign "BIO_new"
      Ctypes.(ptr void @-> returning t)

    let s_mem = foreign "BIO_s_mem"
      Ctypes.(void @-> returning (ptr void))

    let read = foreign "BIO_read"
      Ctypes.(t @-> ptr char @-> int @-> returning int)

    let write = foreign "BIO_write"
      Ctypes.(t @-> string @-> int @-> returning int)
  end

  module ASN1_object = struct
    let t = Ctypes.(ptr void)

    let obj2nid = foreign "OBJ_obj2nid"
      Ctypes.(t @-> returning int)

    (* returns pointer to statically-allocated string, do not free (source: obj_dat.[hc]
       in openssl source) *)
    let nid2sn = foreign "OBJ_nid2sn"
      Ctypes.(int @-> returning string_opt)
  end

  module ASN1_string = struct
    let t = Ctypes.(ptr void)

    let length = foreign "ASN1_STRING_length"
      Ctypes.(t @-> returning int)

    (* returns internal pointer, do not free (source: manpage of ASN1_STRING_data(3)) *)
    let data = foreign "ASN1_STRING_data"
      Ctypes.(t @-> returning string)
  end

  module X509_name_entry = struct
    let t = Ctypes.(ptr void)

    (* returns pointer to field in [t], do not free (source: x509name.c in openssl
       source) *)
    let get_object = foreign "X509_NAME_ENTRY_get_object"
      Ctypes.(t @-> returning ASN1_object.t)

    (* returns pointer to field in [t], do not free (source: x509name.c in openssl
       source) *)
    let get_data = foreign "X509_NAME_ENTRY_get_data"
      Ctypes.(t @-> returning ASN1_string.t)
  end

  module X509_name = struct
    let t = Ctypes.(ptr void)

    let entry_count = foreign "X509_NAME_entry_count"
      Ctypes.(t @-> returning int)

    (* returns internal pointer, do not free (source: manpage of
       X509_NAME_get_entry(3)) *)
    let get_entry = foreign "X509_NAME_get_entry"
      Ctypes.(t @-> int @-> returning X509_name_entry.t)
  end

  module X509 = struct
    let t = Ctypes.(ptr void)

    (* returns internal pointer, do not free (source: manpage of
       X509_get_subject_name(3)) *)
    let get_subject_name = foreign "X509_get_subject_name"
      Ctypes.(t @-> returning X509_name.t)

    let verify_cert_error_string = foreign "X509_verify_cert_error_string"
      Ctypes.(long @-> returning string_opt)

    let free = foreign "X509_free"
      Ctypes.(t @-> returning void)
  end

  module Ssl_session = struct
    let t = Ctypes.(ptr void)

    (* free with SSL_SESSION_free() (source: manpage of SSL_SESSION_free(3)) *)
    let new_ = foreign "SSL_SESSION_new"
      Ctypes.(void @-> returning t)

    let free = foreign "SSL_SESSION_free"
      Ctypes.(t @-> returning void)
  end

  module Ssl =
  struct
    let t = Ctypes.(ptr void)

    (* free with SSL_free() (source: manpage of SSL_free(3)) *)
    let new_ = foreign "SSL_new"
      Ctypes.(Ssl_ctx.t @-> returning t)

    let free = foreign "SSL_free"
      Ctypes.(t @-> returning void)

    let set_method = foreign "SSL_set_ssl_method"
      Ctypes.(t @-> ptr void @-> returning int)

    let get_error = foreign "SSL_get_error"
      Ctypes.(ptr void @-> int @-> returning int)

    let set_connect_state = foreign "SSL_set_connect_state"
      Ctypes.(t @-> returning void)

    let set_accept_state = foreign "SSL_set_accept_state"
      Ctypes.(t @-> returning void)

    let connect = foreign "SSL_connect"
      Ctypes.(t @-> returning int)

    let accept = foreign "SSL_accept"
      Ctypes.(t @-> returning int)

    let set_bio = foreign "SSL_set_bio"
      Ctypes.(t @-> Bio.t @-> Bio.t @-> returning void)

    let read = foreign "SSL_read"
      Ctypes.(t @-> ptr char @-> int @-> returning int)

    let write = foreign "SSL_write"
      Ctypes.(t @-> string @-> int @-> returning int)

    let use_certificate_file = foreign "SSL_use_certificate_file"
      Ctypes.(t @-> string @-> int @-> returning int)

    let use_private_key_file = foreign "SSL_use_PrivateKey_file"
      Ctypes.(t @-> string @-> int @-> returning int)

    let set_verify = foreign "SSL_set_verify"
      Ctypes.(t @-> int @-> ptr void @-> returning void)

    (* free with X509_free() (source: manpage of SSL_get_peer_certificate(3)) *)
    let get_peer_certificate = foreign "SSL_get_peer_certificate"
      Ctypes.(t @-> returning X509.t)

    let get_verify_result = foreign "SSL_get_verify_result"
      Ctypes.(t @-> returning long)

    let get_version = foreign "SSL_get_version"
      Ctypes.(t @-> returning string)

    let set_session = foreign "SSL_set_session"
      Ctypes.(t @-> Ssl_session.t @-> returning int)

    let session_reused = foreign "SSL_session_reused"
      Ctypes.(t @-> returning int)

    (* free with SSL_session_free() (source: manpage of SSL_get1_session(3)) *)
    let get1_session = foreign "SSL_get1_session"
      Ctypes.(t @-> returning Ssl_session.t)

    let check_private_key = foreign "SSL_check_private_key"
      Ctypes.(t @-> returning int)

    let set_tlsext_host_name = foreign "SSL_set_tlsext_host_name"
      Ctypes.(t @-> ptr char @-> returning int)
  end
end
