open Ctypes_packed
type 'a fn = 'a
val foreign : string -> ('a -> 'b) Ctypes.fn -> ('a -> 'b)
val foreign_value : string -> 'a Ctypes.typ -> 'a Ctypes.ptr
