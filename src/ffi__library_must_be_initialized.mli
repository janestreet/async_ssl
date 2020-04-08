(** OpenSSL FFI modeled after Rust's OpenSSL FFI
    <https://github.com/sfackler/rust-openssl/blob/master/ssl/ffi.rs>.

    For streaming this stuff, see:
    <http://funcptr.net/2012/04/08/openssl-as-a-filter-%28or-non-blocking-openssl%29/>

    This module is for use with Async, which has no threads. You void your warranty
    by calling any of these functions from multiple threads at the same time.

    You MUST call [Initialize.initialize ()] before calling any of these functions.
*)
open! Core

open! Async
open Ctypes
open! Import

module Ssl_error : sig
  type t =
    | Zero_return
    | Want_read
    | Want_write
    | Want_connect
    | Want_accept
    | Want_X509_lookup
    | Syscall_error
    | Ssl_error
  [@@deriving sexp_of]
end

module Ssl_ctx : sig
  type t [@@deriving sexp_of]

  (** Initialize a new SSL context, out of which all SSL connections are allocated. *)
  val create_exn : Version.t -> t

  (** Set options on the SSL context, see [Opt] for available options.  Currently used for
      disabling protocol versions. *)
  val set_options : t -> Opt.t list -> unit

  (** Specifies the locations for the context, at which CA certificates for verification
      purposes are located.  The certificates available via [ca_file] and [ca_path] are
      trusted.

      When used in a server the certificates are used, if necessary, to fill in holes when
      the server is building its own certificate chain. For this use-case they need not be
      CA certificates, and in fact will likely need to include intermediate certificates.

      If [ca_file] is not [None], it points to a file of CA certificates in PEM format.
      It may have more than one certificate.

      If [ca_path] is not [None], it points to a directory containing CA certificates in
      PEM format.  The files each contain one CA certificate.  The certificates in
      [ca_path] are only looked up lazily, not eagarly.

      Prepare the directory [/some/where/certs] containing several CA certificates for use
      as [ca_path]:

      [{
      cd /some/where/certs
      c_rehash .
      }]

      If both [ca_file] and [ca_path] are specified, the certificates in [ca_file] will be
      searched before the certificates in [ca_path].

      If this function is not used, [set_default_verify_paths] should be called to use
      OpenSSL's compiled-in defaults. *)
  val load_verify_locations
    :  ?ca_file:string
    -> ?ca_path:string
    -> t
    -> unit Or_error.t Deferred.t

  (** Tell OpenSSL to use its compiled-in defaults for locating CA certificates for
      verification purposes.  This should be called if [load_verify_locations] is not
      used. *)
  val set_default_verify_paths : t -> unit

  (** Set context within which session can be reused, e.g. the name of the application
      and/or the hostname and/or service name, etc. Server side only.

      https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_set_session_id_context.html *)
  val set_session_id_context : t -> string -> unit

  (** Set the certificate and key file to prove one's identity. These will often be files
      ending with [.pem] and [.key] *)
  val use_certificate_chain_and_key_files
    :  crt_file:string
    -> key_file:string
    -> t
    -> unit Deferred.Or_error.t
end

module Bio : sig
  type t [@@deriving sexp_of]

  (** Create a new 'infinite' memory-backed IO queue, to replace a socket that openssl
      traditionally needs. *)
  val create : unit -> t

  (** Read some bytes from a BIO.

      Returns either the amount of data successfully read (if the return value is
      positive) or that no data was successfully read if the result is 0 or -1.  If the
      return value is -2 then the operation is not implemented in the specific BIO
      type. *)
  val read : t -> buf:char ptr -> len:int -> int

  (** Write some bytes to a BIO.

      Returns either the amount of data successfully written (if the return value is
      positive) or that no data was successfully written if the result is 0 or -1.  If the
      return value is -2 then the operation is not implemented in the specific BIO
      type. *)
  val write : t -> buf:string -> len:int -> int
end

module ASN1_object : sig
  type t

  val obj2nid : t -> int
  val nid2sn : int -> string
end

module ASN1_string : sig
  type t

  val data : t -> string
end

module X509_name_entry : sig
  type t

  val get_object : t -> ASN1_object.t
  val get_data : t -> ASN1_string.t
end

module X509_name : sig
  type t

  val entry_count : t -> int
  val get_entry : t -> int -> X509_name_entry.t
end

module X509 : sig
  type t

  val get_subject_name : t -> X509_name.t
  val get_subject_alt_names : t -> string list
end

module Ssl_session : sig
  type t

  val create_exn : unit -> t
end

module Dh : sig
  type t

  val create : prime:[ `hex of string ] -> generator:[ `hex of string ] -> t
  val generate_parameters : prime_len:int -> generator:int -> unit -> t
end

module Ec_key : sig
  module Curve : sig
    type t [@@deriving sexp]

    val to_string : t -> string
    val of_string : string -> t
    val secp384r1 : t
    val secp521r1 : t
    val prime256v1 : t
  end

  type t

  val new_by_curve_name : Curve.t -> t
end

module Rsa : sig
  type t

  val generate_key : key_length:int -> exponent:int -> unit -> t
end

(* Represents an SSL connection. This follows the naming convention of libopenssl, but
   would perhaps better be named [Connection]. *)
module Ssl : sig
  type t [@@deriving sexp_of]

  (** Creates a new SSL connection, with a memory-backed BIO. *)
  val create_exn : Ssl_ctx.t -> t

  (** Sets a different crypto method for this particular ssl connection. *)
  val set_method : t -> Version.t -> unit

  (** Prepare the ssl connection for an initial handshake - either as a server ([`Accept])
      or as a client ([`Connect]). *)
  val set_initial_state : t -> [ `Connect | `Accept ] -> unit

  val connect : t -> (unit, Ssl_error.t) Result.t
  val accept : t -> (unit, Ssl_error.t) Result.t

  (** Set the binary IO buffers associated with an SSL connection. *)
  val set_bio : t -> input:Bio.t -> output:Bio.t -> unit

  (** Read from the SSL application side. *)
  val read : t -> buf:char ptr -> len:int -> (int, Ssl_error.t) Result.t

  (** Write to the SSL application side. *)
  val write : t -> buf:string -> len:int -> (int, Ssl_error.t) Result.t

  val check_private_key : t -> unit Or_error.t
  val set_verify : t -> Verify_mode.t list -> unit
  val get_peer_certificate : t -> X509.t option

  (* Returns Ok () if there is no peer certificate. *)

  val get_verify_result : t -> unit Or_error.t
  val get_version : t -> Version.t
  val session_reused : t -> bool
  val set_session : t -> Ssl_session.t -> unit Or_error.t
  val get1_session : t -> Ssl_session.t option
  val set_tlsext_host_name : t -> string -> unit Or_error.t

  (** Set the list of available ciphers for client or server connections.
      This is really [SSL_set_cipher_list t (String.concat ~sep:":" ("-ALL" ::  ciphers))]. *)

  val set_cipher_list_exn : t -> string list -> unit

  module Tmp_dh_callback : Foreign.Funptr with type fn = t -> bool -> int -> Dh.t

  val set_tmp_dh_callback : t -> Tmp_dh_callback.t -> unit
  val set_tmp_ecdh : t -> Ec_key.t -> unit

  module Tmp_rsa_callback : Foreign.Funptr with type fn = t -> bool -> int -> Rsa.t

  val set_tmp_rsa_callback : t -> Tmp_rsa_callback.t -> unit
  val get_cipher_list : t -> string list
  val get_peer_certificate_chain : t -> string option
end

(** Pops all errors off of the openssl error stack, returning them as a list of
    human-readable strings.  The most recent errors will be at the head of the list. *)
val get_error_stack : unit -> string list
