(** The protocol and security level that libopenssl uses. *)

open Core.Std

(** Best practice: Try your application with [Tlsv1_2].  That might not work.
    Use [Sslv23] for maximum compatibility.  See SSL_CTX_new(3) for more
    details.

    [SSLv2] was banned by RFC 6176 which contains a dire list of its
    shortcomings.
*)
type t =
  (* Sslv3 or above, historic name. *)
  | Sslv23
  | Sslv3
  | Tlsv1
  | Tlsv1_1
  | Tlsv1_2
with sexp_of, compare

val default : t
