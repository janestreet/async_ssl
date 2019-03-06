open! Core

(** Initialize the async_ssl library. This MUST be called before making any calls in
    [Ffi__library_must_be_initialized]. It is idempotent. *)
val initialize : unit -> unit
