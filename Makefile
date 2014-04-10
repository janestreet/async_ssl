export USE_CAMLP4=yes
export OCAMLMAKEFILE = ./OCamlMakefile
export THREADS=yes
export CFLAGS=-Wall -Wno-deprecated-declarations
export PACKS=sexplib.syntax,sexplib,pa_ounit.syntax,pa_ounit,pa_bench.syntax,\
pa_bench,herelib.syntax,herelib,ctypes.stubs,async,core
export LIB_PACK_NAME=Async_ssl
export CLIBS=ssl crypto
export OCAMLDEP = ocamldep -package $(PACKS) -syntax camlp4o
export OCAMLFLAGS = -syntax camlp4o
export LIBINSTALL_FILES = lib/ffi.mli lib/ssl.mli lib/version.mli \
		   Async_ssl.cmi Async_ssl.cmo Async_ssl.cmx	  \
		   async_ssl.cma async_ssl.cmxa async_ssl.a	  \
		   META

ifndef SUBPROJS
   export SUBPROJS = stubgen async_ssl
endif

define PROJ_stubgen
  RESULT=stubgen
  SOURCES=lib/import.ml				\
	  lib/version.ml      lib/version.mli	\
	  lib/ffi_bindings.ml			\
	  lib/ffi_stubgen.ml
endef
export PROJ_stubgen

define PROJ_async_ssl
  RESULT=async_ssl
  INCDIRS = $(shell ocamlfind query ctypes)/..
  SOURCES=lib/import.ml						\
	  lib/version.ml            lib/version.mli		\
	  lib/ffi_bindings.ml					\
          lib/ffi_generated.ml      lib/ffi_generated.mli	\
          lib/ffi_generated_stubs.c				\
	  lib/ffi.ml                lib/ffi.mli			\
	  lib/ssl.ml                lib/ssl.mli			\
	  lib/std.ml
endef
export PROJ_async_ssl

all: stubs byte-code-library native-code-library

install: all
	ocamlfind install async_ssl $(LIBINSTALL_FILES)
uninstall:
	ocamlfind remove async_ssl

stubgen: SUBPROJS=stubgen
stubgen: nc

stubs: stubgen
	./$< -ml > lib/ffi_generated.ml
	./$< -c > lib/ffi_generated_stubs.c

%:
	@$(MAKE) -f $(OCAMLMAKEFILE) subprojs SUBTARGET=$@
