(** An Async-pipe-based interface with OpenSSL.

    This module allows you to create an SSL client and server, with encrypted
    communication between both. *)
open! Core.Std
open! Async.Std

module Version : module type of Version

module Certificate : sig
  type t

  (* Example:
     [ ("C", "US"); ("ST", "NY"); ("L", "NY")
     ; ("O", "Jane Street"); ("CN", "janestreet.com")]

     You probably only care about CN.
  *)
  val subject : t -> (string * string) list
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
*)

val client
  :  ?version:Version.t
  -> ?name:string
  -> ?ca_file:string
  -> ?ca_path:string
  -> ?session:Session.t
  -> app_to_ssl:(string Pipe.Reader.t)
  -> ssl_to_app:(string Pipe.Writer.t)
  -> net_to_ssl:(string Pipe.Reader.t)
  -> ssl_to_net:(string Pipe.Writer.t)
  -> unit
  -> Connection.t Deferred.Or_error.t

val server
  :  ?version:Version.t
  -> ?name:string
  -> ?ca_file:string
  -> ?ca_path:string
  -> crt_file:string
  -> key_file:string
  -> app_to_ssl:(string Pipe.Reader.t)
  -> ssl_to_app:(string Pipe.Writer.t)
  -> net_to_ssl:(string Pipe.Reader.t)
  -> ssl_to_net:(string Pipe.Writer.t)
  -> unit
  -> Connection.t Deferred.Or_error.t
