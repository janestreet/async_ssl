open Base
open Stdio
module C = Configurator.V1

let write_sexp fn sexp = Out_channel.write_all fn ~data:(Sexp.to_string sexp)

let () =
  C.main ~name:"async_ssl" (fun c ->
    let default : C.Pkg_config.package_conf =
      { libs = [ "-lssl"; "-lcrypto" ]; cflags = [] }
    in
    let conf =
      match C.Pkg_config.get c with
      | None -> default
      | Some pc -> Option.value (C.Pkg_config.query pc ~package:"openssl") ~default
    in
    write_sexp "openssl-cclib.sexp" [%sexp (conf.libs : string list)];
    write_sexp "openssl-ccopt.sexp" [%sexp (conf.cflags : string list)];
    Out_channel.write_all "openssl-cclib" ~data:(String.concat conf.libs ~sep:" ");
    Out_channel.write_all "openssl-ccopt" ~data:(String.concat conf.cflags ~sep:" "))
;;
