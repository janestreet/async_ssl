module Ffi_bindings = Async_ssl_bindings.Ffi_bindings

let prefix = "async_ssl_stub"

let prologue = "
#include <openssl/ssl.h>
#include <openssl/err.h>
"

let () =
  print_endline prologue;
  Cstubs.Types.write_c Format.std_formatter (module Ffi_bindings.Types)
