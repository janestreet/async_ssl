open! Core

(** These are the MODP groups specified in RFC3526
    https://tools.ietf.org/html/rfc3526 *)

val modp_1536 : unit -> Ffi__library_must_be_initialized.Dh.t
val modp_2048 : unit -> Ffi__library_must_be_initialized.Dh.t
val modp_3072 : unit -> Ffi__library_must_be_initialized.Dh.t
val modp_4096 : unit -> Ffi__library_must_be_initialized.Dh.t
val modp_6144 : unit -> Ffi__library_must_be_initialized.Dh.t
val modp_8192 : unit -> Ffi__library_must_be_initialized.Dh.t
val modp : int -> Ffi__library_must_be_initialized.Dh.t
