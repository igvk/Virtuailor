
import idc
import idaapi
import idautils
import re
#from BPCondIntel import do_logic

idaapi.require("BPCondIntel") # very important 
if __name__ == '__main__':
    """
    .text:000034D3 8B 0D B0 3E 02 00                    mov     ecx, dword_23EB0    ; 
    .text:000034D9 8B 11                                mov     edx, [ecx]          ; p_vtable_addr = 0x1e6e8 <= [0x23eb0]
    .text:000034DB 8B 52 10                             mov     edx, [edx+10h]      ; vfunct_assign_addr = 0x34db; register_vtable = edx; offset = 0x10
    .text:000034DE 8D 84 24 78 10 00 00                 lea     eax, [esp+1078h]
    .text:000034E5 50                                   push    eax
    .text:000034E6 FF D2                                call    edx                 ; virtual_call_addr = 0x34e6
    """
    do_logic(virtual_call_addr = 0x34e6, register_vtable = None , offset = 0x10,  p_vtable_addr = 0x1e6e8, vfunct_assign_addr = 0x34db)


