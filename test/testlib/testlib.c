#include "testlib.h"

TESTLIB_API void TestFunc0() {
  __asm {
    mov esi, esi
    mov eax, eax
    xor ebx, ebx
    xor edi, edi
  }
  return;
}


TESTLIB_API int TestFunc1(int x, int y) {
  __asm {
    nop
    nop
    mov ecx, 5
L1: nop
    nop
    dec ecx
    cmp ecx, 0
    jne L1
    nop
    nop
  }
  return x+y;
}

TESTLIB_API int TestFunc2(int x, int y) {
  __asm {
    nop
    nop
    mov ecx, 0x667
    mov edx, 5
L1: nop
    nop
    inc ecx
    dec edx
    nop
    nop
    mov ecx, 0x666
    nop
    nop
    cmp edx, 0
    jne L1
    nop
    nop
  }
  return x-y;
}

TESTLIB_API void TestFunc3() {
  __asm {
/*  B1  */
    nop
    nop
    nop
    mov esi, 0x666
    mov eax, 0xA
    mov ebx, 0xB
    mov ecx, 0xC
    jz B3
/*  B2  */
    nop
    inc esi
    inc eax
    inc ebx
    mov ebx, 0xB
    jmp B4
/*  B3  */
B3: nop
    mov ebx, 0xB
    inc ecx
    inc esi
    inc eax
    mov ecx, 0xC
    jnz B3
/*  B4  */
B4: nop
    mov eax, 0xA
    inc ebx
    inc esi
    nop
    nop
    nop
  }
  return;
}

TESTLIB_API int TestFunc4(int x, int y) {
  __asm {
    nop
    mov eax, 666
    mov ecx, 5
L1: nop
    nop
    add al, 0x11
    add ax, 0x1111
    add eax, 0x11111111
    add bl, 0x11
    add bx, 0x1111
    add ebx, 0x11111111
    nop
    xchg eax, ebx
    xchg ecx, edx
    nop
    imul eax, [esi]
    imul ecx, [esi]
    cwd
    cdq
    div esi
    dec ecx
    cmp ecx, 0
    jne L1
    nop
    add ebx, 0xC35C5B5A
    nop
    mov     [ebp+0xC], 0
  }
  return x+y;
}

TESTLIB_API int MatrixMult(int *a, int *b, int *c, int n) {
    int i, j, k;

    for (i=0; i<n; i++)
        for (j=0; j<n; j++)
            for (k=0; k<n; k++)
                //printf("c[%d] += a[%d] * b[%d]\n", i*n+j, i*n+k, j+k*n);
                c[i*n+j] += a[i*n+k] * b[j+k*n];
    return 0;
}


TESTLIB_API int FuncFullOfGadgets(int x, int y) {
  __asm {
    nop
    xor eax, 0x0d909090 // 1st: nop; nop; nop; or eax, 0x9090ED35; ret
    xor eax, 0xC39090ED // 2nd:                          nop; nop; ret
    nop
    xor eax, 0xE0FF4342 // inc edx; inc ebx; jmp eax
    nop
    xor eax, 0x23FF4140 // inc eax; inc ecx; jmp [ebx]
    nop
    xor ebx, 0xC35C5B5A // pop edx; pop ebx; pop esp; ret
    nop
    xor ebx, 0x0666C25A // pop edx; ret 0x666
    nop
    xor eax, 0xD1FF4342 // inc edx; inc ebx; call ecx
    nop
    xor eax, 0x10FF4140 // inc eax; inc ecx; call [eax]
    nop
    xor eax, 0x00FF4342 // inc edx; inc ebx; inc [eax] - no gadget here!!
    nop
  }
  return x+y;           // pop ebx; pop ebp; ret
}

#define db _asm _emit

TESTLIB_API int FuncFullOfInsPrefixes(int x, int y) {
  __asm {
    nop
    and edx,edx
    // Group 1: lock and repeat prefixes
    db 0xF0 db 0x21 db 0xD2  // lock
    db 0xF2 db 0x21 db 0xD2  // repne
    db 0xF3 db 0x21 db 0xD2  // rep
    // Group 2: segment override prefixes and branch hints
    db 0x2E db 0x21 db 0xD2
    db 0x36 db 0x21 db 0xD2
    db 0x3E db 0x21 db 0xD2
    db 0x26 db 0x21 db 0xD2
    db 0x64 db 0x21 db 0xD2
    db 0x65 db 0x21 db 0xD2
    db 0x2E db 0x21 db 0xD2
    db 0x3E db 0x21 db 0xD2
    // Group 3: operand-size override prefix
    db 0x66 db 0x21 db 0xD2
    // Group 4: address-size override prefix
    db 0x67 db 0x21 db 0xD2
    nop
    nop
  }
  return x+y;           // pop ebx; pop ebp; ret
}

TESTLIB_API int FuncFullOfEquivalentIns(int x, int y) {
  __asm {
    nop
    // ADC r/m8,r8 <-> ADC r8,r/m8
    db 0x10 db 0xC1
    db 0x12 db 0xC1
    // ADC r/m16/32,r16/32 <-> ADC r16/32, r/m16/32
    db 0x11 db 0xC2
    db 0x13 db 0xC2
    // x + y = x - (-y)
    add dl, 0x66
    sub dl, 0x66
    add edx, 0x66666666
    sub edx, 0x66666666
    add edx, 0x66
    sub edx, 0x66
    add al, 0x66
    sub al, 0x66
    add eax, 0x66666666
    sub eax, 0x66666666
    nop
    nop
  }
  return x+y;           // pop ebx; pop ebp; ret
}

TESTLIB_API void FuncFullOfReordering() {
  __asm {
    nop
    // corresponds to the example in slide 4 of this slide deck:
    // http://www-rohan.sdsu.edu/~taoxie/cs572/Lec22.pdf
    // F0 -> eax
    // F2 -> ebx
    // F3 -> edx
    // R1 -> esi
    mov eax, [esi]
    mov edx, [eax+ebx]
    mov [esi], edx
    mov eax, [esi+8]
    mov edx, [eax+ebx]
    mov [esi+8], edx
    jnz L1
    // corresponds to the example in Fig 9.3 (p.270) in Muchnick's
    // Advanced Compiler Design and Implementation
    //  r1 -> eax
    //  r2 -> ebx
    //  r3 -> ecx
    //  r4 -> edx
    //  r5 -> esi
    //  r6 -> edi
    // r12 -> ebp
    // r15 -> esp
    mov ebx, [eax]      // r2 <- [r1]
    mov ecx, [eax+4]    // r3 <- [r1+4]
    lea edx, [ebx+ecx]  // r4 <- r2 + r3
    lea esi, [ebx-1]    // r5 <- r2 - 1
    // corresponds to the example in Fig 9.4 (p.270) in Muchnick's
    // Advanced Compiler Design and Implementation
L1: nop
    nop
    jnz L2
    mov ecx, [esp]      // r3 <- [r15]
    mov edx, [esp+4]    // r4 <- [r15+4]
    lea ebx, [ecx+edx]  // r2 <- r3 -r4
    mov esi, [ebp]      // r5 <- [r12]
    add ebp, 4          // r12 <- r12 + 4
    lea edi, [ecx+esi]  // r6 <- r3 * r5
    mov [esp+4], ecx    // [r15+4] <- r3
    lea esi, [edi+2]    // r5 <- r6 + 2
L2: nop
    nop
  }
}

TESTLIB_API int JumpAround() {
  __asm {
    jmp START
L1: inc eax
    jmp L2
L3: add eax, 666
    jmp L4
L5: dec eax
    jmp L6
L7: sub eax, 50
    jmp L8
L9: imul eax, 2
    jmp END
  }
  
  __asm mov eax, 0 __asm mov eax, 0 __asm mov eax, 0 __asm mov eax, 0
  __asm mov eax, 0 __asm mov eax, 0 __asm mov eax, 0 __asm mov eax, 0
  __asm mov eax, 0 __asm mov eax, 0 __asm mov eax, 0 __asm mov eax, 0
  __asm mov eax, 0 __asm mov eax, 0 __asm mov eax, 0 __asm mov eax, 0
  __asm mov eax, 0 __asm mov eax, 0 __asm mov eax, 0 __asm mov eax, 0
  __asm mov eax, 0 __asm mov eax, 0 __asm mov eax, 0 __asm mov eax, 0
  
  __asm {
START:
    mov eax, 0
    jmp L1
L2: mov ecx, 532
    sub eax, ecx
    jmp L3
L4: inc eax
    jmp L5
L6: dec eax
    jmp L7
L8: shr eax, 2
    jmp L9
END:
  }
}

