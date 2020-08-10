open! Base

[%%import "config.h"]

module Voidp (T : sig
    val name : string
  end) : sig
  type t [@@deriving sexp_of]

  val t : t Ctypes.typ
  val t_opt : t option Ctypes.typ
end = struct
  type t = unit Ctypes.ptr

  let t = Ctypes.(ptr void)
  let t_opt = Ctypes.(ptr_opt void)

  let sexp_of_t t =
    [%sexp (T.name : string), (Ctypes.raw_address_of_ptr t : Base.Nativeint.Hex.t)]
  ;;
end

module Bignum = Voidp (struct
    let name = "Bignum"
  end)

module Ssl = Voidp (struct
    let name = "Ssl"
  end)

module Rsa = Voidp (struct
    let name = "Rsa"
  end)

module Dh = Voidp (struct
    let name = "Dh"
  end)

module Progress_callback =
  (val Foreign.dynamic_funptr Ctypes.(int @-> int @-> ptr void @-> returning void))

module Tmp_dh_callback =
  (val Foreign.dynamic_funptr Ctypes.(Ssl.t @-> bool @-> int @-> returning Dh.t))

module Tmp_rsa_callback =
  (val Foreign.dynamic_funptr Ctypes.(Ssl.t @-> bool @-> int @-> returning Rsa.t))

module Types (F : Cstubs.Types.TYPE) = struct
  module Ssl_op = struct
    let no_sslv2 = F.constant "SSL_OP_NO_SSLv2" F.ulong
    let no_sslv3 = F.constant "SSL_OP_NO_SSLv3" F.ulong
    let no_tlsv1 = F.constant "SSL_OP_NO_TLSv1" F.ulong
    let no_tlsv1_1 = F.constant "SSL_OP_NO_TLSv1_1" F.ulong
    let no_tlsv1_2 = F.constant "SSL_OP_NO_TLSv1_2" F.ulong
  end

  module Verify_mode = struct
    let verify_none = F.constant "SSL_VERIFY_NONE" F.int
    let verify_peer = F.constant "SSL_VERIFY_PEER" F.int
    let verify_fail_if_no_peer_cert = F.constant "SSL_VERIFY_FAIL_IF_NO_PEER_CERT" F.int
    let verify_client_once = F.constant "SSL_VERIFY_CLIENT_ONCE" F.int
  end

  module Verify_result = struct
    (* Other codes should be obtained with X509.verify_cert_error_string *)
    let ok = F.constant "X509_V_OK" F.long
  end

  module Ssl_error = struct
    let none = F.constant "SSL_ERROR_NONE" F.int
    let zero_return = F.constant "SSL_ERROR_ZERO_RETURN" F.int
    let want_read = F.constant "SSL_ERROR_WANT_READ" F.int
    let want_write = F.constant "SSL_ERROR_WANT_WRITE" F.int
    let want_connect = F.constant "SSL_ERROR_WANT_CONNECT" F.int
    let want_accept = F.constant "SSL_ERROR_WANT_ACCEPT" F.int
    let want_x509_lookup = F.constant "SSL_ERROR_WANT_X509_LOOKUP" F.int
    let syscall = F.constant "SSL_ERROR_SYSCALL" F.int
    let ssl = F.constant "SSL_ERROR_SSL" F.int
  end

  module X509_filetype = struct
    let pem = F.constant "X509_FILETYPE_PEM" F.int
    let asn1 = F.constant "X509_FILETYPE_ASN1" F.int
  end
end

module Bindings (F : Cstubs.FOREIGN) = struct
  let foreign = F.foreign

  module Ctypes = struct
    include Ctypes

    let ( @-> ) = F.( @-> )
    let returning = F.returning
    let foreign = F.foreign
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
    include Voidp (struct
        let name = "Ssl_method"
      end)

    let dummy name () = failwith (Printf.sprintf "Ssl_method %s not implemented" name)
    let implemented name = foreign name Ctypes.(void @-> returning t)
    let helper name f = f name

    [%%ifdef JSC_TLS_method]

    let tls = helper "TLS_method" implemented

    [%%elif defined JSC_SSLv23_method]

    let tls = helper "SSLv23_method" implemented

    [%%else]

    let tls = helper "TLS_method" dummy

    [%%endif]

    let sslv23 = tls

    [%%if defined JSC_SSLv3_method]

    let sslv3 = helper "SSLv3_method" implemented

    [%%else]

    let sslv3 = helper "SSLv3_method" dummy

    [%%endif]
    [%%if defined JSC_TLSv1_method]

    let tlsv1 = helper "TLSv1_method" implemented

    [%%else]

    let tlsv1 = helper "TLSv1_method" dummy

    [%%endif]
    [%%if defined JSC_TLSv1_1_method]

    let tlsv1_1 = helper "TLSv1_1_method" implemented

    [%%else]

    let tlsv1_1 = helper "TLSv1_1_method" dummy

    [%%endif]
    [%%if defined JSC_TLSv1_2_method]

    let tlsv1_2 = helper "TLSv1_2_method" implemented

    [%%else]

    let tlsv1_2 = helper "TLSv1_2_method" dummy

    [%%endif]

    (* SSLv2 isn't secure, so we don't use it.  If you really really really need it, use
       SSLv23 which will at least try to upgrade the security whenever possible.

       let sslv2_method  = foreign "SSLv2_method"  ssl_method_t
    *)
  end

  let err_get_error = foreign "ERR_get_error" Ctypes.(void @-> returning ulong)

  let err_error_string_n =
    foreign "ERR_error_string_n" Ctypes.(ulong @-> ptr char @-> int @-> returning void)
  ;;

  let add_all_digests = foreign "OpenSSL_add_all_digests" Ctypes.(void @-> returning void)
  let add_all_ciphers = foreign "OpenSSL_add_all_ciphers" Ctypes.(void @-> returning void)

  let add_ssl_algorithms =
    foreign "OpenSSL_add_ssl_algorithms" Ctypes.(void @-> returning void)
  ;;

  let openssl_config = foreign "OPENSSL_config" Ctypes.(string_opt @-> returning void)
  let init = foreign "SSL_library_init" Ctypes.(void @-> returning ulong)

  let ssl_load_error_strings =
    foreign "SSL_load_error_strings" Ctypes.(void @-> returning void)
  ;;

  let err_load_crypto_strings =
    foreign "ERR_load_crypto_strings" Ctypes.(void @-> returning void)
  ;;

  module Engine = struct
    let load_builtin_engines =
      foreign "ENGINE_load_builtin_engines" Ctypes.(void @-> returning void)
    ;;

    let unregister_RAND =
      foreign "ENGINE_unregister_RAND" Ctypes.(void @-> returning void)
    ;;

    let register_all_complete =
      foreign "ENGINE_register_all_complete" Ctypes.(void @-> returning void)
    ;;
  end

  module Ssl_ctx = struct
    include Voidp (struct
        let name = "Ssl_ctx"
      end)

    (* free with SSL_CTX_free() (source: manpage of SSL_CTX_free(3)) *)
    let new_ = foreign "SSL_CTX_new" Ctypes.(Ssl_method.t @-> returning t_opt)
    let free = foreign "SSL_CTX_free" Ctypes.(t @-> returning void)

    let load_verify_locations =
      foreign
        "SSL_CTX_load_verify_locations"
        Ctypes.(t @-> string_opt @-> string_opt @-> returning int)
    ;;

    let set_default_verify_paths =
      foreign "SSL_CTX_set_default_verify_paths" Ctypes.(t @-> returning int)
    ;;

    let set_session_id_context =
      foreign
        "SSL_CTX_set_session_id_context"
        Ctypes.(t @-> ptr char @-> uint @-> returning int)
    ;;

    let set_cipher_list =
      foreign "SSL_CTX_set_cipher_list" Ctypes.(t @-> string @-> returning int)
    ;;

    let set_options =
      foreign "SSL_CTX_set_options" Ctypes.(t @-> ulong @-> returning ulong)
    ;;

    let use_certificate_chain_file =
      foreign "SSL_CTX_use_certificate_chain_file" Ctypes.(t @-> string @-> returning int)
    ;;

    let use_certificate_file =
      foreign
        "SSL_CTX_use_certificate_file"
        Ctypes.(t @-> string @-> int @-> returning int)
    ;;

    let use_private_key_file =
      foreign
        "SSL_CTX_use_PrivateKey_file"
        Ctypes.(t @-> string @-> int @-> returning int)
    ;;

  end

  module Bio = struct
    include Voidp (struct
        let name = "Bio"
      end)

    (* for use in ctypes signatures *)

    (* Returns a [BIO *] that is later assigned to an [SSL] object by calling
       SSL_set_bio(3).  The [BIO *] is freed automatically when calling SSL_free().
       (source: manpage of SSL_free(3)) *)
    let new_ = foreign "BIO_new" Ctypes.(ptr void @-> returning t)
    let s_mem = foreign "BIO_s_mem" Ctypes.(void @-> returning (ptr void))
    let read = foreign "BIO_read" Ctypes.(t @-> ptr char @-> int @-> returning int)
    let write = foreign "BIO_write" Ctypes.(t @-> string @-> int @-> returning int)
  end

  module ASN1_object = struct
    include Voidp (struct
        let name = "ASN1_object"
      end)

    let obj2nid = foreign "OBJ_obj2nid" Ctypes.(t @-> returning int)

    (* returns pointer to statically-allocated string, do not free (source: obj_dat.[hc]
       in openssl source) *)
    let nid2sn = foreign "OBJ_nid2sn" Ctypes.(int @-> returning string_opt)
    let txt2nid = foreign "OBJ_txt2nid" Ctypes.(string @-> returning int)
  end

  module ASN1_string = struct
    include Voidp (struct
        let name = "ASN1_string"
      end)

    let length = foreign "ASN1_STRING_length" Ctypes.(t @-> returning int)

    (* returns internal pointer, do not free (source: manpage of ASN1_STRING_data(3)) *)
    let data = foreign "ASN1_STRING_data" Ctypes.(t @-> returning string)
  end

  module X509_name_entry = struct
    include Voidp (struct
        let name = "X509_name_entry"
      end)

    (* returns pointer to field in [t], do not free (source: x509name.c in openssl
       source) *)
    let get_object =
      foreign "X509_NAME_ENTRY_get_object" Ctypes.(t @-> returning ASN1_object.t)
    ;;

    (* returns pointer to field in [t], do not free (source: x509name.c in openssl
       source) *)
    let get_data =
      foreign "X509_NAME_ENTRY_get_data" Ctypes.(t @-> returning ASN1_string.t)
    ;;
  end

  module X509_name = struct
    include Voidp (struct
        let name = "X509_name"
      end)

    let entry_count = foreign "X509_NAME_entry_count" Ctypes.(t @-> returning int)

    (* returns internal pointer, do not free (source: manpage of
       X509_NAME_get_entry(3)) *)
    let get_entry =
      foreign "X509_NAME_get_entry" Ctypes.(t @-> int @-> returning X509_name_entry.t)
    ;;
  end

  module X509 = struct
    include Voidp (struct
        let name = "X509"
      end)

    (* returns internal pointer, do not free (source: manpage of
       X509_get_subject_name(3)) *)
    let get_subject_name =
      foreign "X509_get_subject_name" Ctypes.(t @-> returning X509_name.t_opt)
    ;;

    let verify_cert_error_string =
      foreign "X509_verify_cert_error_string" Ctypes.(long @-> returning string_opt)
    ;;

    let free = foreign "X509_free" Ctypes.(t @-> returning void)

    let subject_alt_names =
      foreign
        "async_ssl__subject_alt_names"
        Ctypes.(t @-> returning (ptr_opt (ptr_opt char)))
    ;;

    let free_subject_alt_names =
      foreign
        "async_ssl__free_subject_alt_names"
        Ctypes.(ptr (ptr_opt char) @-> returning void)
    ;;
  end

  module Ssl_session = struct
    include Voidp (struct
        let name = "Ssl_session"
      end)

    (* free with SSL_SESSION_free() (source: manpage of SSL_SESSION_free(3)) *)
    let new_ = foreign "SSL_SESSION_new" Ctypes.(void @-> returning t_opt)
    let free = foreign "SSL_SESSION_free" Ctypes.(t @-> returning void)
  end

  module Bignum = struct
    include Bignum

    let new_ = foreign "BN_new" Ctypes.(void @-> returning t_opt)
    let free = foreign "BN_free" Ctypes.(t @-> returning void)
    let bin2bn = foreign "BN_bin2bn" Ctypes.(ptr char @-> int @-> t @-> returning t)
    let hex2bn = foreign "BN_hex2bn" Ctypes.(ptr t_opt @-> string @-> returning int)
  end

  module Progress_callback = Progress_callback

  module Dh = struct
    include Dh

    let new_ = foreign "DH_new" Ctypes.(void @-> returning t_opt)
    let free = foreign "DH_free" Ctypes.(t @-> returning void)

    let generate_parameters =
      foreign
        "DH_generate_parameters"
        Ctypes.(int @-> int @-> Progress_callback.t_opt @-> ptr void @-> returning t_opt)
    ;;

    module Struct = struct
      type t

      let t : t Ctypes.structure Ctypes.typ = Ctypes.structure "DH"

      (*_ a bunch of fields we don't care about but we need for ctypes to not break *)
      let _pad = Ctypes.field t "pad" Ctypes.int
      let _version = Ctypes.field t "version" Ctypes.int

      (*_ we actually need these two fields to be able to create [DH*] values *)
      let p = Ctypes.field t "p" Bignum.t
      let g = Ctypes.field t "g" Bignum.t

      (*_ lots more fields that we don't care about *)

      let () = Ctypes.seal t
    end
  end

  module Ec_key = struct
    include Voidp (struct
        let name = "Ec_key"
      end)

    let new_by_curve_name =
      foreign "EC_KEY_new_by_curve_name" Ctypes.(int @-> returning t_opt)
    ;;

    let free = foreign "EC_KEY_free" Ctypes.(t @-> returning void)
  end

  module Rsa = struct
    include Rsa

    let generate_key =
      foreign
        "RSA_generate_key"
        Ctypes.(int @-> int @-> Progress_callback.t_opt @-> ptr void @-> returning t_opt)
    ;;

    let free = foreign "RSA_free" Ctypes.(t @-> returning void)
  end

  module Ssl = struct
    include Ssl

    (* free with SSL_free() (source: manpage of SSL_free(3)) *)
    let new_ = foreign "SSL_new" Ctypes.(Ssl_ctx.t @-> returning t_opt)
    let free = foreign "SSL_free" Ctypes.(t @-> returning void)

    let set_method =
      foreign "SSL_set_ssl_method" Ctypes.(t @-> Ssl_method.t @-> returning int)
    ;;

    let get_error = foreign "SSL_get_error" Ctypes.(t @-> int @-> returning int)
    let set_connect_state = foreign "SSL_set_connect_state" Ctypes.(t @-> returning void)
    let set_accept_state = foreign "SSL_set_accept_state" Ctypes.(t @-> returning void)
    let connect = foreign "SSL_connect" Ctypes.(t @-> returning int)
    let accept = foreign "SSL_accept" Ctypes.(t @-> returning int)
    let set_bio = foreign "SSL_set_bio" Ctypes.(t @-> Bio.t @-> Bio.t @-> returning void)
    let read = foreign "SSL_read" Ctypes.(t @-> ptr char @-> int @-> returning int)
    let write = foreign "SSL_write" Ctypes.(t @-> string @-> int @-> returning int)

    let set_verify =
      foreign "SSL_set_verify" Ctypes.(t @-> int @-> ptr void @-> returning void)
    ;;

    let set_cipher_list =
      foreign "SSL_set_cipher_list" Ctypes.(t @-> string @-> returning int)
    ;;

    let get_cipher_list =
      foreign "SSL_get_cipher_list" Ctypes.(t @-> int @-> returning string_opt)
    ;;

    module Tmp_dh_callback = Tmp_dh_callback

    let set_tmp_dh_callback =
      foreign
        "SSL_set_tmp_dh_callback"
        Ctypes.(t @-> Tmp_dh_callback.t @-> returning void)
    ;;

    let set_tmp_ecdh =
      foreign "SSL_set_tmp_ecdh" Ctypes.(t @-> Ec_key.t @-> returning void)
    ;;

    module Tmp_rsa_callback = Tmp_rsa_callback

    let set_tmp_rsa_callback =
      foreign
        "SSL_set_tmp_rsa_callback"
        Ctypes.(t @-> Tmp_rsa_callback.t @-> returning void)
    ;;

    (* free with X509_free() (source: manpage of SSL_get_peer_certificate(3)) *)
    let get_peer_certificate =
      foreign "SSL_get_peer_certificate" Ctypes.(t @-> returning X509.t_opt)
    ;;

    let get_verify_result = foreign "SSL_get_verify_result" Ctypes.(t @-> returning long)
    let get_version = foreign "SSL_get_version" Ctypes.(t @-> returning string)

    let set_session =
      foreign "SSL_set_session" Ctypes.(t @-> Ssl_session.t @-> returning int)
    ;;

    let session_reused = foreign "SSL_session_reused" Ctypes.(t @-> returning int)

    (* free with SSL_session_free() (source: manpage of SSL_get1_session(3)) *)
    let get1_session =
      foreign "SSL_get1_session" Ctypes.(t @-> returning Ssl_session.t_opt)
    ;;

    let check_private_key = foreign "SSL_check_private_key" Ctypes.(t @-> returning int)

    let set_tlsext_host_name =
      foreign "SSL_set_tlsext_host_name" Ctypes.(t @-> ptr char @-> returning int)
    ;;

    let pem_peer_certificate_chain =
      foreign
        "async_ssl__pem_peer_certificate_chain"
        Ctypes.(t @-> returning (ptr_opt char))
    ;;

    let free_pem_peer_certificate_chain =
      foreign
        "async_ssl__free_pem_peer_certificate_chain"
        Ctypes.(ptr char @-> returning void)
    ;;
  end
end
