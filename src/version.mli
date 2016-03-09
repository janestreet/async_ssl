(** The protocol and security level that libopenssl uses. *)

open! Core.Std

(** Best practice: Try your application with [Tlsv1_2].  That might not work.
    Use [Sslv23] for maximum compatibility.  See SSL_CTX_new(3) for more
    details.

    [SSLv2] was banned by RFC 6176 which contains a dire list of its
    shortcomings.

    Older versions of OpenSSL do not support Tlsv1_1 and Tlsv1_2. You will be
    able to link with such a version, but will get an error about an undefined
    symbol at runtime if you try using the unsupported version.
*)
type t =
  (* Sslv3 or above, historic name. *)
  | Sslv23
  | Sslv3
  | Tlsv1
  | Tlsv1_1
  | Tlsv1_2
[@@deriving sexp, compare]

val default : t
