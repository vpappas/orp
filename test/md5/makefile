all: main.exe

md5.lib: md5c.c md5.h
	cl /Femd5.dll md5c.c /D MD5_DLLEXPORT /link /DLL

main.exe: main.c md5.lib
	cl main.c md5.lib

md5_main.exe: md5_main.c md5.lib
	cl md5_main.c md5.lib

clean:
	del *.exe *.dll *.obj *.lib *.exp

ida_clean:
	del *.idb *.til *.nam *.id0 *.id1
