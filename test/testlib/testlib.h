#ifndef _TESTLIB_H_
#define _TESTLIB_H_

#ifdef TESTLIB_DLLEXPORT
#define TESTLIB_API __declspec(dllexport)
#else
#define TESTLIB_API
#endif

TESTLIB_API int TestFunc1(int, int);
TESTLIB_API int TestFunc2(int, int);
TESTLIB_API void TestFunc3();
TESTLIB_API int TestFunc4(int, int);
TESTLIB_API int MatrixMult(int *, int *, int *, int);
TESTLIB_API int FuncFullOfGadgets(int, int);
TESTLIB_API int FuncFullOfInsPrefixes(int, int);
TESTLIB_API int FuncFullOfEquivalentIns(int, int);
TESTLIB_API void FuncFullOfReordering();
TESTLIB_API int JumpAround();

#endif
