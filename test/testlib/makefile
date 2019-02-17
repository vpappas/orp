
all: main.exe 

testlib.lib: testlib.c testlib.h
	cl /Fetestlib.dll testlib.c /D TESTLIB_DLLEXPORT /link /DLL

main.exe: main.c testlib.lib
	cl main.c testlib.lib

clean:
	rm *.exe *.dll *.obj *.lib *.exp

ida_clean:
	rm *.idb *.til *.nam *.id0 *.id1
