open! Core
open! Async
open! Import

module Client : sig
  type t [@@deriving sexp_of]

  val create
    :  ?verify_modes:Verify_mode.t list
    -> ?tls_options:Opt.t list
    -> ?allowed_ciphers:[ `Secure | `Openssl_default | `Only of string list ]
    -> ?crt_file:string
    -> ?key_file:string
    -> ?session:Ssl.Session.t
    -> ?connection_name:string
         (** Break glass if you are stuck using a certificate/encryption that openssl
             considers insecure. Only set this in exceptional circumstances. *)
    -> ?override_security_level:Ssl.Override_security_level.t
    -> ?alpn_protocols:string list
    -> remote_hostname:string option
    -> ca_file:string option
    -> ca_path:string option
    -> verify_callback:(Ssl.Connection.t -> unit Deferred.Or_error.t)
    -> unit
    -> t

  val remote_hostname : t -> string option
  val allowed_ciphers : t -> [ `Secure | `Openssl_default | `Only of string list ]

  (** [ca_file] and [ca_path] may both be used, in which case [ca_file] is searched first,
      followed by [ca_path]. See [man SL_CTX_load_verify_locations]. *)
  val ca_file : t -> string option

  val ca_path : t -> string option
  val crt_file : t -> string option
  val key_file : t -> string option
  val tls_version : t -> Version.t
  val tls_options : t -> Opt.t list
  val verify_modes : t -> Verify_mode.t list
  val verify_callback : t -> Ssl.Connection.t -> unit Deferred.Or_error.t
  val session : t -> Ssl.Session.t option
  val connection_name : t -> string option
  val override_security_level : t -> Ssl.Override_security_level.t option
  val alpn_protocols : t -> string list option
end

module Server : sig
  type t [@@deriving sexp_of]

  val create
    :  ?verify_modes:Verify_mode.t list
    -> ?tls_options:Opt.t list
    -> ?allowed_ciphers:[ `Secure | `Openssl_default | `Only of string list ]
         (** Break glass if you are stuck using a certificate/encryption that openssl
             considers insecure. Only set this in exceptional circumstances. *)
    -> ?override_security_level:Ssl.Override_security_level.t
    -> ?alpn_protocols:string list
    -> crt_file:string
    -> key_file:string
    -> ca_file:string option
    -> ca_path:string option
    -> unit
    -> t

  val allowed_ciphers : t -> [ `Secure | `Openssl_default | `Only of string list ]
  val ca_file : t -> string option
  val ca_path : t -> string option
  val crt_file : t -> string
  val key_file : t -> string
  val tls_version : t -> Version.t
  val tls_options : t -> Opt.t list
  val verify_modes : t -> Verify_mode.t list option
  val override_security_level : t -> Ssl.Override_security_level.t option
  val alpn_protocols : t -> string list option
end
