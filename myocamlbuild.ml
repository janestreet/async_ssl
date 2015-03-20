(* OASIS_START *)
(* OASIS_STOP *)

let dispatch = function
  | After_rules ->
    let stubgen = "stubgen/ffi_stubgen.byte" in

    rule "generated ml"
      ~dep:stubgen
      ~prod:"lib/ffi_generated.ml"
      (fun _ _ ->
         Cmd(S[P stubgen; A"-ml"; Sh">"; A"lib/ffi_generated.ml"]));

    rule "generated c"
      ~dep:stubgen
      ~prod:"lib/ffi_generated_stubs.c"
      (fun _ _ ->
         Cmd(S[P stubgen; A"-c"; Sh">"; A"lib/ffi_generated_stubs.c"]));

    flag ["c"; "compile"] & S[A"-I"; A"lib"; A"-package"; A"ctypes"]

  | _ ->
    ()

let () = Ocamlbuild_plugin.dispatch (fun hook -> dispatch hook; dispatch_default hook)
