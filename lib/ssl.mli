(** An Async-pipe-based interface with OpenSSL.

    This module allows you to create an SSL client and server, with encrypted
    communication between both. *)
open Core.Std
open Async.Std

module Version : module type of Version

(** Creates either an SSL client or server.

    [version] is optional, and allows you to customize the specific version of SSL
    that this connection should be using.

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

    To close the connection and free associated memory, just close the passed pipes.

    A [unit Deferred.t] is returned, which is determined when ssl has cleaned up. *)

val client
  :  ?version:Version.t
  -> ?name:string
  -> ?ca_file:string
  -> ?ca_path:string
  -> app_to_ssl:(string Pipe.Reader.t)
  -> ssl_to_app:(string Pipe.Writer.t)
  -> net_to_ssl:(string Pipe.Reader.t)
  -> ssl_to_net:(string Pipe.Writer.t)
  -> unit
  -> unit Deferred.t

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
  -> unit Deferred.t
