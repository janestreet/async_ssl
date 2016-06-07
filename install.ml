#use "topfind";;
#require "js-build-tools.oasis2opam_install";;

open Oasis2opam_install;;

generate ~package:"async_ssl"
  [ oasis_lib "async_ssl"
  ; oasis_lib "async_ssl_bindings"
  ; file "META" ~section:"lib"
  ; file "_build/namespace_wrappers/ctypes_packed.cmi" ~section:"lib"
  ; file "_build/namespace_wrappers/ctypes_cstubs.cmi" ~section:"lib"
  ]
