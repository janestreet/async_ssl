type 'a fn = 'a
val foreign : string -> ('a -> 'b) Ctypes.fn -> ('a -> 'b)
