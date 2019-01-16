open! Core

type t =
  | Verify_none
  | Verify_peer
  | Verify_fail_if_no_peer_cert
  | Verify_client_once
[@@deriving sexp_of]
