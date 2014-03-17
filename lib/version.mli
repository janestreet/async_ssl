(** The protocol and security level that libopenssl uses. *)

open Core.Std

(** Best practice: Try your application with [Tlsv1].  That might not work.  Use [Sslv23]
    for maximum compatibility.  See SSL_CTX_new(3) for more details. *)
type t =
  (** [SSLv2] was banned by RFC 6176 which contains a dire list of its shortcomings. *)
  | Sslv3
  | Tlsv1
  | Sslv23
with sexp_of
