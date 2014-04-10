USE_CAMLP4=yes

PACKS=sexplib.syntax,sexplib,pa_ounit.syntax,pa_ounit,pa_bench.syntax,pa_bench,herelib.syntax,herelib,ctypes.foreign,ctypes,async,core

CLIBS=ssl crypto

OCAMLDEP = ocamldep -package $(PACKS) -syntax camlp4o
OCAMLFLAGS = -syntax camlp4o -thread
RESULT=async_ssl
LIB_PACK_NAME=Async_ssl

SOURCES=lib/import.ml				\
	lib/version.ml      lib/version.mli	\
        lib/ffi_bindings.ml			\
	lib/ffi.ml          lib/ffi.mli		\
	lib/ssl.ml          lib/ssl.mli		\
	lib/std.ml

LIBINSTALL_FILES = lib/ffi.mli lib/ssl.mli lib/version.mli \
                   Async_ssl.cmi Async_ssl.cmo Async_ssl.cmx \
                   async_ssl.cma async_ssl.cmxa async_ssl.a \
                   META

all: byte-code-library native-code-library

install: libinstall

-include OCamlMakefile
