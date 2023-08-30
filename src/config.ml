open! Core
open! Async
open! Import

module Client = struct
  type t =
    { remote_hostname : string option
    ; allowed_ciphers : [ `Secure | `Openssl_default | `Only of string list ]
    ; ca_file : string option
    ; ca_path : string option
    ; crt_file : string option
    ; key_file : string option
    ; tls_version : Version.t
    ; tls_options : Opt.t list
    ; verify_modes : Verify_mode.t list
    ; verify_callback : Ssl.Connection.t -> unit Deferred.Or_error.t
    ; session : (Ssl.Session.t[@sexp.opaque]) option
    ; connection_name : string option
    ; override_security_level : (Ssl.Override_security_level.t[@sexp.opaque]) option
    ; alpn_protocols : string list option
    }
  [@@deriving sexp_of, fields ~getters ~iterators:create]

  let create
    ?(verify_modes = [ Verify_mode.Verify_peer ])
    ?(tls_options = Opt.[ No_sslv2; No_sslv3; No_tlsv1; No_tlsv1_1 ])
    ?(allowed_ciphers = `Secure)
    ?crt_file
    ?key_file
    ?session
    ?connection_name
    ?override_security_level
    ?alpn_protocols
    ~remote_hostname
    ~ca_file
    ~ca_path
    ~verify_callback
    ()
    =
    Fields.create
      ~remote_hostname
      ~allowed_ciphers
      ~ca_file
      ~ca_path
      ~crt_file
      ~key_file
      ~session
      ~connection_name
      ~tls_version:Version.Tls
      ~tls_options
      ~verify_modes
      ~verify_callback
      ~override_security_level
      ~alpn_protocols
  ;;
end

module Server = struct
  type t =
    { allowed_ciphers : [ `Secure | `Openssl_default | `Only of string list ]
    ; ca_file : string option
    ; ca_path : string option
    ; crt_file : string
    ; key_file : string
    ; tls_version : Version.t
    ; tls_options : Opt.t list
    ; verify_modes : Verify_mode.t list option
    ; override_security_level : (Ssl.Override_security_level.t[@sexp.opaque]) option
    ; alpn_protocols : string list option
    }
  [@@deriving sexp_of, fields ~getters ~iterators:create]

  let create
    ?verify_modes
    ?(tls_options = Opt.[ No_sslv2; No_sslv3; No_tlsv1; No_tlsv1_1 ])
    ?(allowed_ciphers = `Secure)
    ?override_security_level
    ?alpn_protocols
    ~crt_file
    ~key_file
    ~ca_file
    ~ca_path
    ()
    =
    Fields.create
      ~verify_modes
      ~allowed_ciphers
      ~ca_file
      ~ca_path
      ~crt_file
      ~key_file
      ~tls_version:Version.Tls
      ~tls_options
      ~override_security_level
      ~alpn_protocols
  ;;
end
