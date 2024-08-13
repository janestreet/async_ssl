/* This code is necessary to make the ocaml bindings portable across
 * versions of OpenSSL.
 * This program is run only during build and outputs defines/undefs based on the
 * availability of [*_method]s and [SSL_OPT_NO_*], so that we can replace ocaml code
 * that would reference these with no-ops.
 */
#include <stdio.h>
#include <openssl/ssl.h>
#include <dlfcn.h>

void* open_ssl_library() {
  void *handle;
  SSL_library_init();
  handle = dlopen(NULL,RTLD_NOW|RTLD_GLOBAL);
  if (!handle) {
    fprintf(stderr, "dlopen failed\n");
    exit(1);
  }
  return handle;
}

int function_defined(void* handle, char*const symbol) {
  const SSL_METHOD * (*fun)(void);
  char *error = NULL;
  dlerror();
  *(void **) (&fun) = dlsym(handle, symbol);
  return (!((error = dlerror()) != NULL));
}

int main ( int __attribute__((unused)) argc, char __attribute__((unused)) **argv ) {
  void *handle;
  int success = 0;

  handle = open_ssl_library();


  /*$
   open Core;;

   let witness_defined name =  [%string {|printf("#define JSC_%{name}\n"); success++;|}];;
   let witness_undef name =  [%string {|printf("#undef JSC_%{name}\n");|}];;

   [ "SSLv23_method"
   ; "TLS_method"
   ; "SSLv3_method"
   ; "TLSv1_method"
   ; "TLSv1_1_method"
   ; "TLSv1_2_method"
   ; "TLSv1_3_method"
   ] |> List.iter ~f:(fun sym -> print_endline [%string {|
   if(function_defined(handle, "%{sym}")) {
     %{witness_defined sym};
   } else {
     %{witness_undef sym};
   }
   |}]);;

   [ "SSL_OP_NO_SSLv2"
   ; "SSL_OP_NO_SSLv3"
   ; "SSL_OP_NO_TLSv1"
   ; "SSL_OP_NO_TLSv1_1"
   ; "SSL_OP_NO_TLSv1_2"
   ; "SSL_OP_NO_TLSv1_3"
   ; "SSL_OP_SINGLE_DH_USE"
   ; "SSL_OP_SINGLE_ECDH_USE"
   ] |> List.iter ~f:(fun sym -> print_endline [%string {|
   #ifdef %{sym}
     %{witness_defined sym}
   #else
     %{witness_undef sym}
   #endif
   |}]);;
   */
   if(function_defined(handle, "SSLv23_method")) {
     printf("#define JSC_SSLv23_method\n"); success++;;
   } else {
     printf("#undef JSC_SSLv23_method\n");;
   }
   

   if(function_defined(handle, "TLS_method")) {
     printf("#define JSC_TLS_method\n"); success++;;
   } else {
     printf("#undef JSC_TLS_method\n");;
   }
   

   if(function_defined(handle, "SSLv3_method")) {
     printf("#define JSC_SSLv3_method\n"); success++;;
   } else {
     printf("#undef JSC_SSLv3_method\n");;
   }
   

   if(function_defined(handle, "TLSv1_method")) {
     printf("#define JSC_TLSv1_method\n"); success++;;
   } else {
     printf("#undef JSC_TLSv1_method\n");;
   }
   

   if(function_defined(handle, "TLSv1_1_method")) {
     printf("#define JSC_TLSv1_1_method\n"); success++;;
   } else {
     printf("#undef JSC_TLSv1_1_method\n");;
   }
   

   if(function_defined(handle, "TLSv1_2_method")) {
     printf("#define JSC_TLSv1_2_method\n"); success++;;
   } else {
     printf("#undef JSC_TLSv1_2_method\n");;
   }
   

   if(function_defined(handle, "TLSv1_3_method")) {
     printf("#define JSC_TLSv1_3_method\n"); success++;;
   } else {
     printf("#undef JSC_TLSv1_3_method\n");;
   }
   

   #ifdef SSL_OP_NO_SSLv2
     printf("#define JSC_SSL_OP_NO_SSLv2\n"); success++;
   #else
     printf("#undef JSC_SSL_OP_NO_SSLv2\n");
   #endif
   

   #ifdef SSL_OP_NO_SSLv3
     printf("#define JSC_SSL_OP_NO_SSLv3\n"); success++;
   #else
     printf("#undef JSC_SSL_OP_NO_SSLv3\n");
   #endif
   

   #ifdef SSL_OP_NO_TLSv1
     printf("#define JSC_SSL_OP_NO_TLSv1\n"); success++;
   #else
     printf("#undef JSC_SSL_OP_NO_TLSv1\n");
   #endif
   

   #ifdef SSL_OP_NO_TLSv1_1
     printf("#define JSC_SSL_OP_NO_TLSv1_1\n"); success++;
   #else
     printf("#undef JSC_SSL_OP_NO_TLSv1_1\n");
   #endif
   

   #ifdef SSL_OP_NO_TLSv1_2
     printf("#define JSC_SSL_OP_NO_TLSv1_2\n"); success++;
   #else
     printf("#undef JSC_SSL_OP_NO_TLSv1_2\n");
   #endif
   

   #ifdef SSL_OP_NO_TLSv1_3
     printf("#define JSC_SSL_OP_NO_TLSv1_3\n"); success++;
   #else
     printf("#undef JSC_SSL_OP_NO_TLSv1_3\n");
   #endif
   

   #ifdef SSL_OP_SINGLE_DH_USE
     printf("#define JSC_SSL_OP_SINGLE_DH_USE\n"); success++;
   #else
     printf("#undef JSC_SSL_OP_SINGLE_DH_USE\n");
   #endif
   

   #ifdef SSL_OP_SINGLE_ECDH_USE
     printf("#define JSC_SSL_OP_SINGLE_ECDH_USE\n"); success++;
   #else
     printf("#undef JSC_SSL_OP_SINGLE_ECDH_USE\n");
   #endif
   
/*$*/

  if(success == 0) {
    fprintf(stderr, "Not openssl methods were found. Did you link with libssl ?\n");
    exit(1);
  }
  return 0;
}
