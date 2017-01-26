(** OpenSSL context options. *)

open! Core

(** This mli currently only has SSL/TLS protocol version-related options, though it should
    also support additions of any option that can be passed to SSL_CTX_set_options(3) and
    SSL_set_options(3).

    Best practice: Leave the "version" specified as [Sslv23] (see version.mli) and use the
    [No_...] options below to mask off undesired protocol versions.

    The current defaults for [Version] and [Opt] will enable only TLSv1.2.
*)

type t =
  | No_sslv2
  | No_sslv3
  | No_tlsv1
  | No_tlsv1_1
  | No_tlsv1_2
[@@deriving sexp, compare]

val default : t list
