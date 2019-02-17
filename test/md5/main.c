#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "md5.h"

typedef void(*pMD5Update)(MD5_CTX *, unsigned char *, unsigned int);

int main(int argc, char *argv[])
{
  HINSTANCE hInstance;
  pMD5Update pmu = &MD5Update;
  MD5_CTX context;
  unsigned char digest[16];
  char in[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  int i;

  /* if an extra arg is suplied, try to load it as DLL and
   * find the MD5UPdate function in there. */
  if (argc == 2) {

    if (!(hInstance = LoadLibrary(argv[1]))) {
  	  printf("LoadLibrary failed (%d)\n", GetLastError());
  	  return 1;
    }

	pmu = (pMD5Update) GetProcAddress(hInstance, "MD5Update");
    
    if (pmu == NULL) {
  	  printf("GetProcAddress failed (%d)\n", GetLastError());
      return 1;
    }
  }

  MD5Init(&context);
  pmu(&context, in, sizeof(in)-1);
  MD5Final(digest, &context);

  printf ("MD5 (\"%s\") = ", in);

  for (i = 0; i < 16; i++)
    printf ("%02x", digest[i]);

  printf ("\n");

  return 0;
}
