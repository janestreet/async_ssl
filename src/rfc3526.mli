open! Core

(** These are the MODP groups specified in RFC3526
    https://tools.ietf.org/html/rfc3526 *)

val modp_1536 : Ffi.Dh.t
val modp_2048 : Ffi.Dh.t
val modp_3072 : Ffi.Dh.t
val modp_4096 : Ffi.Dh.t
val modp_6144 : Ffi.Dh.t
val modp_8192 : Ffi.Dh.t
val modp : int -> Ffi.Dh.t
