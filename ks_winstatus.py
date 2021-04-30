import typing

import idaapi
import ida_bytes
import ida_enum
import ida_ida
import ida_netnode
import ida_typeinf
import ida_search
import idc


# Changes constants representing known Windows status codes. Sort of.. It only does 0xC000000 codes

# List of type libraries to try
DEFAULT_TYPELIBS = [
    'mssdk_win10',
    'mssdk_win81',
    'mssdk_win8',
    'mssdk_win7'
]

DWORD_MASK = 0xFFFFFFFF

def get_enum_map(eid: int) -> typing.Dict[int, int]:
    """
    Return an IDA enum as a dict

    Adapted from the Ghidra IDA database exporter: 
    https://github.com/NationalSecurityAgency/ghidra/GhidraBuild/IDAPro/Python/6xx/plugins/xmlexp.py

    Args:
        eid (Integer): enum identifier
    Returns:
        typing.Dict[int, int]: { enum_member_value: enum_member_cid }
    """
    enum_map = {}
    mask = DWORD_MASK
    first = True
    for n in range(ida_enum.get_enum_size(eid)):
        if (first == True):
            value = ida_enum.get_first_enum_member(eid, mask)
            first = False
        else:
            value = ida_enum.get_next_enum_member(eid, value, mask)
        (cid, serial) = ida_enum.get_first_serial_enum_member(eid, value, mask)
        main_cid = cid
        while cid != ida_netnode.BADNODE:
            enum_map[value] = cid
            last_value = ida_enum.get_last_enum_member(eid, mask)
            if value == last_value:
                mask = ida_enum.get_next_bmask(eid, mask)
                first = True
            (cid, serial) = ida_enum.get_next_serial_enum_member(serial, main_cid)
    return enum_map

# Load the MACRO_STATUS enumeration
def main():
    
    typelib = None
    for typelib_name in DEFAULT_TYPELIBS:
        typelib = ida_typeinf.load_til(typelib_name)
        if typelib:
            break
    if not typelib:
        print(f"Unable to load mssdk")
        return
    # print(f"Loaded mssdk type library: {typelib.name}")
    
    status_enum = ida_typeinf.import_type(typelib, -1, "MACRO_STATUS")
    if status_enum == ida_netnode.BADNODE:
        print(f"Unable to load type MACRO_STATUS")
    # print(f"Loaded MACRO_STATUS")
    
    # Grab the enum members
    enum_map = get_enum_map(status_enum)
    cur_member_id = ida_enum.get_first_enum_member(status_enum)
    while cur_member_id:
        cur_value = idaapi.get_const_value(cur_member_id)
        enum_map[cur_value] = cur_member_id
        cur_member_id = ida_enum.get_next_enum_member(cur_member_id)

    # Iterate over all untyped immediates
    imm_ea = ida_ida.cvar.inf.min_ea
    while(imm_ea != idaapi.BADADDR):
        imm_ea = ida_search.find_notype(imm_ea, ida_search.SEARCH_NEXT | ida_search.SEARCH_DOWN)[0]
        if ida_bytes.is_code(ida_bytes.get_flags(imm_ea)):
            enum_value = idc.get_operand_value(imm_ea, 1)
            # Only handle likely error types right now..
            if (enum_value & DWORD_MASK) > 0xC0000000:
                try:
                    cid = enum_map[enum_value]
                    # print(f"Applying {hex(enum_value & DWORD_MASK)} at {hex(imm_ea)}")
                    # We don't need the member, we can just apply the enum type to the address
                    ida_bytes.op_enum(imm_ea, 1, status_enum, 0)
                except KeyError:
                    continue   

main()