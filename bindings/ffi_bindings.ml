module Types(F : Cstubs.Types.TYPE) =
struct
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
  let tlsv1_method  = foreign "TLSv1_method" ssl_method_t
  let tlsv1_1_method  = foreign "TLSv1_1_method" ssl_method_t
  let tlsv1_2_method  = foreign "TLSv1_2_method" ssl_method_t
  let sslv23_method = foreign "SSLv23_method" ssl_method_t
  (* SSLv2 isn't secure, so we don't use it.  If you really really really need it, use
     SSLv23 which will at least try to upgrade the security whenever possible.

     let sslv2_method  = foreign "SSLv2_method"  ssl_method_t
  *)

  module Ssl_ctx =
  struct
    let t = Ctypes.(ptr void)

    let new_ = foreign "SSL_CTX_new"
      Ctypes.(ptr void @-> returning (ptr_opt void))

    let free = foreign "SSL_CTX_free"
      Ctypes.(t @-> returning void)

    let load_verify_locations = foreign "SSL_CTX_load_verify_locations"
      Ctypes.(t @-> string_opt @-> string_opt @-> returning int)

    let set_session_id_context = foreign "SSL_CTX_set_session_id_context"
      Ctypes.(t @-> ptr char @-> uint @-> returning int)
  end

  module Bio =
  struct
    let t = Ctypes.(ptr void) (* for use in ctypes signatures *)

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

    let nid2sn = foreign "OBJ_nid2sn"
      Ctypes.(int @-> returning string_opt)
  end

  module ASN1_string = struct
    let t = Ctypes.(ptr void)

    let length = foreign "ASN1_STRING_length"
      Ctypes.(t @-> returning int)

    let data = foreign "ASN1_STRING_data"
      Ctypes.(t @-> returning string)
  end

  module X509_name_entry = struct
    let t = Ctypes.(ptr void)

    let get_object = foreign "X509_NAME_ENTRY_get_object"
      Ctypes.(t @-> returning ASN1_object.t)

    let get_data = foreign "X509_NAME_ENTRY_get_data"
      Ctypes.(t @-> returning ASN1_string.t)
  end

  module X509_name = struct
    let t = Ctypes.(ptr void)

    let entry_count = foreign "X509_NAME_entry_count"
      Ctypes.(t @-> returning int)

    let get_entry = foreign "X509_NAME_get_entry"
      Ctypes.(t @-> int @-> returning X509_name_entry.t)
  end

  module X509 = struct
    let t = Ctypes.(ptr void)

    let get_subject_name = foreign "X509_get_subject_name"
      Ctypes.(t @-> returning X509_name.t)

    let verify_cert_error_string = foreign "X509_verify_cert_error_string"
      Ctypes.(long @-> returning string_opt)
  end

  module Ssl_session = struct
    let t = Ctypes.(ptr void)

    let new_ = foreign "SSL_SESSION_new"
      Ctypes.(void @-> returning t)

    let free = foreign "SSL_SESSION_free"
      Ctypes.(t @-> returning void)
  end

  module Ssl =
  struct
    let t = Ctypes.(ptr void)

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

    let get1_session = foreign "SSL_get1_session"
      Ctypes.(t @-> returning Ssl_session.t)

    let check_private_key = foreign "SSL_check_private_key"
      Ctypes.(t @-> returning int)
  end
end
