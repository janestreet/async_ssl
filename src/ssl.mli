(** An Async-pipe-based interface with OpenSSL.

    This module allows you to create an SSL client and server, with encrypted
    communication between both. *)


open! Core
open! Async
module Version : module type of Version
module Opt : module type of Opt
module Verify_mode : module type of Verify_mode

val secure_ciphers : string list

module Certificate : sig
  type t

  (* Example:
     [ ("C", "US"); ("ST", "NY"); ("L", "NY")
     ; ("O", "Jane Street"); ("CN", "janestreet.com")]

     You probably only care about CN.
  *)

  val subject : t -> (string * string) list
  val subject_alt_names : t -> string list
end

module Session : sig
  type t

  val create : unit -> t
end

(* It is your responsibility to check that the session certificate satisfies
   your expectations (for instance, that the CN (common name) on the certificate
   matches the domain name you are intending to connect to). Same applies to the
   negotiated version of the protocol.
*)
module Connection : sig
  type t [@@deriving sexp_of]

  (* Becomes determined when the ssl session has terminated and cleaned
     up. Includes the error in case of abnormal termination. *)

  val closed : t -> unit Or_error.t Deferred.t

  (* Initiates connection shutdown. *)

  val close : t -> unit

  (* Negotiated version. Not necessarily the same as what we passed as argument
     to the [client] or [server] functions. *)

  val version : t -> Version.t

  (* None if the other side sent us no certificate, Error if validation failed. *)

  val peer_certificate : t -> Certificate.t Or_error.t option
  val pem_peer_certificate_chain : t -> string option
  val session_reused : t -> bool
end


(** Creates either an SSL client or server.

    NB: your achieved security will be very weak unless you check the connection
    parameters after the handshake. See the [Connection] module above.

    [version] is optional, and allows you to customize the specific version of SSL
    that this connection should be using. It may be downgraded - you should
    check the actually negotiated version post-connection.

    [name] allows you to name this connection, to make errors easier to track down.

    If [ca_file] is not [None], it points to a file of CA certificates in PEM format.  It
    may have more than one certificate.

    If [ca_path] is not [None], it points to a directory containing CA certificates in PEM
    format. The files each contain one CA certificate.  The certificates in [ca_path] are
    only looked up lazily, not eagarly.

    If both [ca_file] and [ca_path] are specified, the certificates in [ca_file] will be
    searched before the certificates in [ca_path].

    Any certificate authorities loaded are automatically trusted by OpenSSL.

    [crt_file] and [key_file] are the on-disk locations of the server's public and
    private keys.

    Any data written into [app_to_ssl] will be encrypted with SSL, and the encrypted
    data will eventually be written into [ssl_to_net].

    Similarly, any data written into [net_to_ssl] will be decrypted with SSL and written
    into [ssl_to_app].

    A picture is probably easier to understand:

    {v

                          app_to_ssl           ssl_to_net
        +---------------+ ---------> +-------+ ---------> +-----+
        | CLIENT/SERVER |            |  SSL  |            | NET |
        +---------------+ <--------- +-------+ <--------- +-----+
                          ssl_to_app           net_to_ssl

      v}

    To close the connection and free associated memory, call
    [Connection.close]. This will close all the involved pipes.

    The [session] argument enables the session resumption mechanism: when called
    with the same session value twice, the client will try to resume the session
    during the second call, resulting in a quicker handshake. It is your
    responsibility to keep the mapping between the destinations and the sessions
    to be used with them. Calling the client with the same [session] but with a
    differet [ca_file] or [ca_path] will result in an error. Use
    [Connection.session_reused] to find out if session resumption actually worked.

    Both [client] and [server] become determined when the handshake has completed.

    The [hostname] sets the hostname to pass to the server using the SNI extension.
*)


val client
  :  ?version:Version.t
  -> ?options:Opt.t list
  -> ?name:string
  -> ?hostname:string
  (** Use [allowed_ciphers] to control which ciphers should be used.  See CIPHERS(1), and
      `openssl ciphers -v`.

      If unspecified, [allowed_ciphers] defaults to [`Secure], which is a list derived
      from guidance posted on https://cipherli.st/ and is meant to be adjusted over time
      to reflect current security practices.  The current list is available via
      [secure_ciphers].

      If you need to keep a old cipher enabled across an update of the [`Secure] cipher
      list or a default value change[1], you can do something like the following:

      [`Only (Ssl.secure_ciphers @ ["OLD_CIPHER"])]

      [1] Historically, [allowed_ciphers] was not a mandatory argument and [`Secure] was
      not the default for backwards-compatibility reasons. However, in early 2018
      [`Secure] became the default to at least force users to think about this if they
      want something less secure. *)
  -> ?allowed_ciphers:[ `Secure | `Openssl_default | `Only of string list ]
  -> ?ca_file:string
  -> ?ca_path:string
  -> ?crt_file:string
  -> ?key_file:string
  (** Use [verify_modes] to control what verification SSL does as part of the handshake.
      To see the full description of the available options see the notes on the manpage
      for SSL_CTX_set_verify(3) on your system.

      Historically, this was an optional argument with no default. However, the fact that
      SSL does *no* verification in that case makes it extremely easy to gain a false
      sense of security regarding the level of verification that is being done, so the
      default is now [Verify_peer].

      To restore the old, insecure, behavior (or to do the verification yourself), set
      this to [Verify_none]. *)
  -> ?verify_modes:Verify_mode.t list
  -> ?session:Session.t
  -> app_to_ssl:string Pipe.Reader.t
  -> ssl_to_app:string Pipe.Writer.t
  -> net_to_ssl:string Pipe.Reader.t
  -> ssl_to_net:string Pipe.Writer.t
  -> unit
  -> Connection.t Deferred.Or_error.t

val server
  :  ?version:Version.t
  -> ?options:Opt.t list
  -> ?name:string
  (** Use [allowed_ciphers] to control which ciphers should be used. See comment in
      [client] above for more details. *)
  -> ?allowed_ciphers:[ `Secure | `Openssl_default | `Only of string list ]
  -> ?ca_file:string
  -> ?ca_path:string
  -> crt_file:string
  -> key_file:string
  (** Use [verify_modes] to control what verification SSL does as part of the handshake.
      The default for servers is [Verify_none], meaning no client certificate request is
      sent to the client. *)
  -> ?verify_modes:Verify_mode.t list
  -> app_to_ssl:string Pipe.Reader.t
  -> ssl_to_app:string Pipe.Writer.t
  -> net_to_ssl:string Pipe.Reader.t
  -> ssl_to_net:string Pipe.Writer.t
  -> unit
  -> Connection.t Deferred.Or_error.t

module For_testing : sig
  val slow_down_io_to_exhibit_truncation_bugs : bool ref
end
