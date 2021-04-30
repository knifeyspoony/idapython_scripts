import idautils
import ida_bytes
import idaapi

for ea in idautils.Heads():
    if ida_bytes.is_code(ida_bytes.get_flags(ea)) and idaapi.is_call_insn(ea):
        idaapi.set_item_color(ea, 0xFFFFFFA0)