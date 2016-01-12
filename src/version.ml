open! Core.Std
open! Import

type t =
  | Sslv23
  | Sslv3
  | Tlsv1
  | Tlsv1_1
  | Tlsv1_2
[@@deriving sexp, compare]

let default = Tlsv1
