(* https://www.openssl.org/docs/man3.0/man3/X509_check_host.html *)

type t =
  | AlwaysCheckSubject
  | NeverCheckSubject
  | NoWildcards
  | NoPartialWildcards
  | MultiLabelWildcards
  | SingleLabelSubdomains
[@@deriving sexp_of]
