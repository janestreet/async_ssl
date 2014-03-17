open Core.Std  let _ = _squelch_unused_module_warning_
open Import    let _ = _squelch_unused_module_warning_

type t =
  | Sslv3
  | Tlsv1
  | Sslv23
with sexp_of
