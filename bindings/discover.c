#include <stdio.h>
#include <openssl/ssl.h>
#include <dlfcn.h>

static char * const symbol[] = { "SSLv3_method",
                                 "SSLv23_method",
                                 "TLSv1_method",
                                 "TLSv1_1_method",
                                 "TLSv1_2_method",
};

static int size = sizeof(symbol) / sizeof(symbol[0]);

int main ( int argc, char **argv ) {
  void *handle;
  const SSL_METHOD * (*fun)(void);
  char *error = NULL;
  int i;
  int success = 0;
  SSL_library_init();
  handle = dlopen(NULL,RTLD_NOW|RTLD_GLOBAL);
  if (!handle) {
    fprintf(stderr, "dlopen failed\n");
    exit(1);
  }
  for(i = 0; i < size; i++){
    dlerror();
    *(void **) (&fun) = dlsym(handle, symbol[i]);
    if ((error = dlerror()) != NULL) {
      printf("#let JSC_%s = false\n", symbol[i]);
    }
    else {
      printf("#let JSC_%s = true\n", symbol[i]);
      success++;
    }
  }
  if(success == 0) {
    fprintf(stderr, "Not openssl methods were found. Did you link with libssl ?\n");
    exit(1);
  }
  return 0;
}
