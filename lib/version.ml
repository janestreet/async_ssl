open Core.Std  let _ = _squelch_unused_module_warning_
open Import    let _ = _squelch_unused_module_warning_

type t =
  | Sslv23
  | Sslv3
  | Tlsv1
  | Tlsv1_1
  | Tlsv1_2
with sexp_of, compare

let default = Tlsv1

