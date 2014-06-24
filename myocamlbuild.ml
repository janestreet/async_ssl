(* OASIS_START *)
(* OASIS_STOP *)

let dispatch = function
  | After_rules ->
    rule "generated ml"
      ~dep:"lib/ffi_stubgen.byte"
      ~prod:"lib/ffi_generated.ml"
      (fun _ _ ->
         Cmd(S[P"lib/ffi_stubgen.byte"; A"-ml"; Sh">"; A"lib/ffi_generated.ml"]));

    rule "generated c"
      ~dep:"lib/ffi_stubgen.byte"
      ~prod:"lib/ffi_generated_stubs.c"
      (fun _ _ ->
         Cmd(S[P"lib/ffi_stubgen.byte"; A"-c"; Sh">"; A"lib/ffi_generated_stubs.c"]))

  | _ ->
    ()

let () = Ocamlbuild_plugin.dispatch (fun hook -> dispatch hook; dispatch_default hook)
