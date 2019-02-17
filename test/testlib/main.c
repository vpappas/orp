#include <windows.h>
#include <stdio.h>
#include <strsafe.h>
#include "testlib.h"

#define N 3

typedef int(*pMatrixMult)(int *, int *, int *, int);
void ErrorExit(LPTSTR lpszFunction);

int main(int argc, char *argv[]) {

  HINSTANCE hInstance;
  pMatrixMult pmm = &MatrixMult;
  int a[]={1,2,3,1,2,3,1,2,3},
      b[]={4,5,6,4,5,6,4,5,6},
      c[]={0,0,0,0,0,0,0,0,0};
  int i;

  /* if an extra arg is suplied, try to load it as DLL and
   * find the MatrixMult function in there. */
  if (argc == 2) {

    if (!(hInstance = LoadLibrary(argv[1]))) {
      ErrorExit(TEXT("LoadLibrary"));
    }

	  pmm = (pMatrixMult) GetProcAddress(hInstance, "MatrixMult");

    if (pmm == NULL) {
      ErrorExit(TEXT("GetProcAddress"));
    }
  }

  pmm(&a[0], &b[0], &c[0], N);

  for (i=0; i<N*N; i++)
      printf("%d ", c[i]);
  printf("\n");

  return 0;
}


void ErrorExit(LPTSTR lpszFunction) {

  LPVOID lpMsgBuf;
  DWORD error_no = GetLastError();

  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
      FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error_no,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);
  printf("ERROR - %s: %s", lpszFunction, lpMsgBuf);
  fflush(stdout);

  LocalFree(lpMsgBuf);
  ExitProcess(error_no);
}
