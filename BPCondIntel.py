# This is the breakpoint condition code.
# Every value inside the <<< >>> is an argument that will be replaced by "vtableAddress.py"
# The arguments are:
#    * start_addr -> The offset of the virtual call from the beginning of its segment
#    * register_vtable -> The register who points to the vtable
#    * offset -> The offset of the relevant function from the vtable base pointer

import idautils

value_of_addr = lambda ea: idc.read_dbg_qword(ea) if idaapi.get_inf_structure().is_64bit() else idc.get_wide_dword(ea)
get_pc_value = lambda: int(idc.get_reg_value('rip')) if idaapi.get_inf_structure().is_64bit() else int(idc.get_reg_value('eip'))
get_segment_range = lambda name: (idaapi.get_segm_by_name(name).startEA, idaapi.get_segm_by_name(name).endEA)
get_ptr_size = lambda: 8 if idaapi.get_inf_structure().is_64bit() else 4


def get_fixed_name_for_object(address, prefix=''):
    """
    :param address: string, the object's address we want to calculate its offset
    :param prefix: string, a prefix for the object name
    :param suffix: string, a suffix for the object name
    :return: returns the new name of the object with calculated offset from the base addr -> "prefix + offset + suffix"
      !! In case the object (in this case function) doesn't starts with "sub_" the returned name will be the old name
    """
    name = idc.Name(int(address))
    demangle_name = idc.demangle_name(name, idc.get_inf_attr(idc.INF_LONG_DN))
    calc_func_name = int(address) - idc.get_segm_start(int(address))
    if (name[:4] == "sub_" or name == "" or demangle_name) and ('vtable' not in name):
        name = prefix + hex(calc_func_name)[2:].rstrip('L') + 'h'  # The name will be the offset from the beginning of the segment
    print '[?] new name: %s 0x%X' % (name, int(address))

    return name


def get_vtable_and_vfunc_addr(is_brac, register_vtable, offset):
    """
    :param is_brac: number, if the call/ assignment is byRef the value is -1
    :param register_vtable: string, the register used in the virtual call
    :param offset: number, the offset of the function in the vtables used in on the bp opcode
    :return: return the addresses of the vtable and the virtual function from the relevant register
    """
    if is_brac == -1:  # check it in both start addr and bp if both are [] than anf just than change is_brac
        p_vtable_addr = idc.get_reg_value(register_vtable)
    else:
        p_vtable_addr = value_of_addr(idc.get_reg_value(register_vtable))

    pv_func_addr = p_vtable_addr + offset
    v_func_addr = value_of_addr(pv_func_addr)
    return p_vtable_addr, v_func_addr


def add_comment_to_struct_members(struct_id, vtable_func_offset, start_address):
    # add comment to the vtable struct members
    cur_cmt = idc.get_member_cmt(struct_id, vtable_func_offset, 1)
    new_cmt = ""
    if cur_cmt:
        if cur_cmt[:23] != "Was called from offset:":
            new_cmt = cur_cmt
        else:
            new_cmt = cur_cmt + ", " + hex(start_address)
    else:
        new_cmt = "Was called from offset: " + hex(start_address)
    succ1 = idc.set_member_cmt(struct_id, vtable_func_offset, new_cmt, 1)
    return succ1


def num_vfuncts(p_vtable_addr):
    n_vfuncts = 0
    start, end = get_segment_range('.text')
    vtable_func_value = value_of_addr(p_vtable_addr)
    ptr_size = get_ptr_size()
    vtable_func_offset = 0
    while vtable_func_value != 0:
        if vtable_func_value < start or vtable_func_value > end:
            break
        vtable_func_value = value_of_addr(p_vtable_addr)
        vtable_func_offset += ptr_size
        vtable_func_value = value_of_addr(p_vtable_addr + vtable_func_offset)
    return (vtable_func_offset / ptr_size)


def add_all_functions_to_struct(start_address, struct_id, p_vtable_addr, offset):
    vtable_func_offset = 0
    ptr_bytes = get_ptr_size()
    vtable_func_value = value_of_addr(p_vtable_addr)
    # Add all the vtable's functions to the vtable struct
    start, end = get_segment_range('.text')
    while vtable_func_value != 0:
        if vtable_func_value < start or vtable_func_value > end:
            break
        v_func_name = idc.get_func_name(vtable_func_value)
        #print '[!] vtable_func_value: %X; v_func_name: %s' % (vtable_func_value, v_func_name)
        if v_func_name == '':
            vtable_func_value = value_of_addr(vtable_func_value)
            v_func_name = idc.get_func_name(vtable_func_value)
            if v_func_name == '':
                print("Error in adding functions to struct, at BP address::", hex(start_address))
        # Change function name
        v_func_name = get_fixed_name_for_object(int(vtable_func_value), "vfunc_")
        idaapi.set_name(vtable_func_value, v_func_name, idaapi.SN_FORCE)
        # Add to structure
        if ptr_bytes == 8:
            succ = idc.add_struc_member(struct_id, v_func_name, vtable_func_offset, FF_QWORD, -1, ptr_bytes)
        else:
            succ = idc.add_struc_member(struct_id, v_func_name, vtable_func_offset, FF_DWORD, -1, ptr_bytes)
        if offset == vtable_func_offset:
            add_comment_to_struct_members(struct_id, vtable_func_offset, start_address)
        vtable_func_offset += ptr_bytes
        vtable_func_value = value_of_addr(p_vtable_addr + vtable_func_offset)


def create_vtable_struct(start_address, vtable_name, p_vtable_addr, offset):
    struct_name = vtable_name + "_struct"
    struct_id = add_struc(-1, struct_name, 0)
    if struct_id != idc.BADADDR:
        add_all_functions_to_struct(start_address, struct_id, p_vtable_addr, offset)
        idc.op_stroff(idautils.DecodeInstruction(get_pc_value()), 1, struct_id, 0)
    else:
        struct_id = ida_struct.get_struc_id(struct_name)
        # Checks if the struct exists, in this case the function offset will be added to the struct
        if struct_id != idc.BADADDR:
            idc.op_stroff(idautils.DecodeInstruction(get_pc_value()), 1, struct_id, 0)
        else:
            print("Failed to create struct: " + struct_name)


def get_rdata_segment():
    rdata_name = ['.rdata', '.rodata']

    rdata_seg = None
    for name in rdata_name:
        rdata_seg = idaapi.get_segm_by_name(name)
        if rdata_seg:
            break
    if not rdata_seg:
        print '[-] Read Only segment NOT found'
        return None
    return rdata_seg


def get_derived_class(vptr):
    ftype = idaapi.get_file_type_name()
    m = None
    demangle_name = None

    if 'ELF' in ftype:
        demangle_name = idc.demangle_name(idc.Name(value_of_addr(idc.prev_head(vptr))), idc.get_inf_attr(idc.INF_LONG_DN))
        if demangle_name:
            m = re.search("`typeinfo for'(.+)", demangle_name)
    elif 'PE' in ftype:
        demangle_name = idc.demangle_name(idc.Name(vptr), idc.get_inf_attr(idc.INF_LONG_DN))
        if demangle_name:
            m = re.search("const (.+)::`vftable'", demangle_name)
    else:
        print '[-] undefined file type: %s' % ftype

    if not demangle_name:
        return 'unknown_class', 'unknown'
    elif m:
        return m.group(1), demangle_name
    else:
        print '[-] undefined demangled name %s at %X' % (demangle_name, vptr)
        return 'unknown_class', demangle_name


def do_logic(virtual_call_addr, register_vtable, offset):
    # Checks if the assignment was beRef or byVal
    virtual_call_addr = int(virtual_call_addr)
    is_brac_assign = idc.print_operand(get_pc_value(), 1).find('[')
    # Checks if the assignment was beRef or byVal

    seg_start_addr = idc.get_segm_start(get_pc_value())
    seg_end_addr = idc.get_segm_end(get_pc_value())

    if virtual_call_addr >= seg_start_addr and virtual_call_addr <= seg_end_addr:
        call_addr = virtual_call_addr
    else:
        call_addr = virtual_call_addr + seg_start_addr
    is_brac_call = idc.print_operand(call_addr, 0).find('[')
    is_brac = -1

    if is_brac_assign != -1 and is_brac_call != -1:
        is_brac = 0
    # Get the adresses of the vtable and the virtual function from the relevant register:
    p_vtable_addr, v_func_addr = get_vtable_and_vfunc_addr(is_brac, register_vtable, offset)

    rdata_seg = get_rdata_segment()
    if not rdata_seg or p_vtable_addr < rdata_seg.startEA or p_vtable_addr > rdata_seg.endEA:
        print '[-] virtual_call_addr: 0x%X, function address 0x%X NOT in .rdata' % (virtual_call_addr, p_vtable_addr)
        return False
    print("[?] p_vtable_addr: %X, v_func_addr: %X" % (p_vtable_addr, v_func_addr))

    class_name, demangle_name = get_derived_class(p_vtable_addr)
    print('[?] class_name: %s, demangle_name: %s' % (class_name, demangle_name))
    if not demangle_name or not class_name:
        return False

    vtable_name = get_fixed_name_for_object(p_vtable_addr, class_name + '_vtable_')
    # Change the virtual function name (only in case the function has IDA's default name)

    if demangle_name == 'unknown':
        idaapi.set_name(p_vtable_addr, vtable_name, idaapi.SN_FORCE)

    v_func_name = get_fixed_name_for_object(v_func_addr, "vfunc_")
    # Change the vtable address name
    idaapi.set_name(v_func_addr, v_func_name, idaapi.SN_FORCE)
    print('[?] vtable_name: %s, v_func_name: %s' % (vtable_name, v_func_name))
    # Add xref of the virtual call
    idc.add_cref(get_pc_value(), v_func_addr, idc.XREF_USER)
    if num_vfuncts(p_vtable_addr):
        # create the vtable struct
        create_vtable_struct(virtual_call_addr, vtable_name, p_vtable_addr, offset)
    comment = '%X -> %s::%s, vptr: %X' % (v_func_addr, class_name.split('_vtable')[0], v_func_name, p_vtable_addr)
    #print '[?] '+ comment
    idc.MakeRptCmt(virtual_call_addr, comment)
    return True


virtual_call_addr = str(<<<start_addr>>>)  # Offset from the beginning of its segment

register_vtable = "<<<register_vtable>>>"
offset = <<<offset>>>
if offset == "*":
    opnd2 = idc.print_operand(virtual_call_addr, 1)
    reg_offset = 0
    place = opnd2.find('+')
    if place != -1:  # if the function is not the first in the vtable
        sep = opnd2.find('*')
        if sep != -1:  # in case the offset is stored as a duplication of a register with a number
            reg_offset = idc.get_reg_value(opnd2[place + 1:sep])
        register = opnd2[opnd2.find('[') + 1:place]
        if reg_offset:
            offset = opnd2[sep + 1:opnd2.find(']')]
            if offset.find('h') != -1:
                int_offset = int(offset[:offset.find('h')], 16)
            else:
                int_offset = int(offset)
            offset = int_offset * reg_offset

        else:
            offset = opnd2[place + 1:opnd2.find(']')]
try:
    do_logic(virtual_call_addr, register_vtable, offset)
except Exception as e:
    print("Error! at BP address: 0x%X (%s)", get_pc_value(), e)
    import sys
    import traceback
    error_class = e.__class__.__name__
    detail = e.args[0]
    cl, exc, tb = sys.exc_info()
    lastCallStack = traceback.extract_tb(tb)[-1]
    fileName = lastCallStack[0]
    lineNum = lastCallStack[1]
    funcName = lastCallStack[2]
    errMsg = "[x] File \"{}\", line {}, in {}: [{}] {}".format(fileName, lineNum, funcName, error_class, detail)
    print(errMsg)

#idc.add_cref(0x000000013FA72ABB, 0x000000013FA71177, idc.XREF_USER | idc.fl_F)
