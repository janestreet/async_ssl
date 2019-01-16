module Ffi_bindings = Async_ssl_bindings.Ffi_bindings

let prologue = "\n#include <openssl/ssl.h>\n#include <openssl/err.h>\n"

let () =
  print_endline prologue;
  Cstubs.Types.write_c Format.std_formatter (module Ffi_bindings.Types)
;;
