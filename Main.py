from __future__ import print_function
import idc
import idautils
import idaapi
import ida_ida

idaapi.require("AddBP")
idaapi.require("vtableAddress")
idaapi.require("GUI")

from vtableAddress import REGISTERS


def get_all_functions():
    for func in idautils.Functions():
        print(hex(func), idc.get_func_name(func))


def get_xref_code_to_func(func_addr):
    a = idautils.XrefsTo(func_addr, 1)
    addr = {}
    for xref in a:
        frm = xref.frm  # ea in func
        start = idc.get_func_attr(frm, idc.FUNCATTR_START)  # to_xref func addr
        func_name = idc.get_func_name(start)  # to_xref func name
        addr[func_name] = [xref.iscode, start]
    return addr


def add_bp_to_virtual_calls(cur_addr, end):
    while cur_addr < end:
        if cur_addr == idc.BADADDR:
            break
        elif idc.print_insn_mnem(cur_addr) == 'call' or idc.print_insn_mnem(cur_addr) == 'BLR':
            if True in [idc.print_operand(cur_addr, 0).find(reg) != -1 for reg in REGISTERS]:  # idc.print_operand(cur_addr, 0) in REGISTERS:
                cond, bp_address = vtableAddress.write_vtable2file(cur_addr)
                if cond != '':
                    bp_vtable = AddBP.add(bp_address, cond)
        cur_addr = idc.next_head(cur_addr)


def set_values(start, end):
    start = start
    end = end
    return start, end


if __name__ == '__main__':
    start_addr_range = ida_ida.inf_get_min_ea()  # You can change the virtual calls address range
    end_addr_range = ida_ida.inf_get_max_ea()
    oldTo = idaapi.set_script_timeout(0)
    # Initializes the GUI: Deletes the 0x in the beginning and the L at the end:
    gui = GUI.VirtuailorBasicGUI(set_values, {'start': hex(start_addr_range)[2:].rstrip('L'), 'end': hex(end_addr_range)[2:].rstrip('L')})
    gui.exec_()
    if gui.start_line.text != "banana":
        print("Virtuailor - Started")
        add_bp_to_virtual_calls(int(gui.start_line.text(), 16), int(gui.stop_line.text(), 16))
        print("Virtuailor - Finished")
