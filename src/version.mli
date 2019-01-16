(** The protocol and security level that libopenssl uses. *)

open! Core

(** Best practice: Leave this at the default of [Tls] to allow negotiation, and use an
    option list ([Opt.t list]) when calling [Ssl.server] or [Ssl.client] to disable
    undesired versions of SSL/TLS.  See opt.mli for more details.

    The current defaults for [Version] and [Opt] will enable only TLSv1.2.

    [Tls] allows negotiation, whereas the other options (besides the deprecated [Sslv23])
    limit the connection to a single protocol version.  See SSL_CTX_new(3) for more
    details.  (If you are on CentOS 6, you should probably use
    https://www.openssl.org/docs/man1.0.1/ssl/SSL_CTX_new.html instead of the system
    manual pages--they appear out-of-date.)

    [SSLv2] was banned by RFC 6176 which contains a dire list of its shortcomings.

    Older versions of OpenSSL do not support Tlsv1_1 and Tlsv1_2. You will be able to link
    with such a version, but will get an error about an undefined symbol at runtime if you
    try using the unsupported version.
*)
type t =
  | Sslv23
  (* Deprecated in favor of [Tls] below, which behaves identically *)
  | Tls
  (* Negotiate highest available version *)
  | Sslv3
  | Tlsv1
  | Tlsv1_1
  | Tlsv1_2
[@@deriving sexp, compare]

val default : t
