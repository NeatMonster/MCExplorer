import ctypes
import os
import sys

import ida_diskio
import ida_funcs
import ida_graph
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_pro


LEVELS = ["MMAT_GENERATED", "MMAT_PREOPTIMIZED", "MMAT_LOCOPT", "MMAT_CALLS",
          "MMAT_GLBOPT1", "MMAT_GLBOPT2", "MMAT_GLBOPT3", "MMAT_LVARS"]

MCODES = ["m_nop", "m_stx", "m_ldx", "m_ldc", "m_mov", "m_neg", "m_lnot",
          "m_bnot", "m_xds", "m_xdu", "m_low", "m_high", "m_add", "m_sub",
          "m_mul", "m_udiv", "m_sdiv", "m_umod", "m_smod", "m_or", "m_and",
          "m_xor", "m_shl", "m_shr", "m_sar", "m_cfadd", "m_ofadd", "m_cfshl",
          "m_cfshr", "m_sets", "m_seto", "m_setp", "m_setnz", "m_setz",
          "m_setae", "m_setb", "m_seta", "m_setbe", "m_setg", "m_setge",
          "m_setl", "m_setle", "m_jcnd", "m_jnz", "m_jz", "m_jae", "m_jb",
          "m_ja", "m_jbe", "m_jg", "m_jge", "m_jl", "m_jle", "m_jtbl",
          "m_ijmp", "m_goto", "m_call", "m_icall", "m_ret", "m_push", "m_pop",
          "m_und", "m_ext", "m_f2i", "m_f2u", "m_i2f", "m_u2f", "m_f2f",
          "m_fneg", "m_fadd", "m_fsub", "m_fmul", "m_fdiv"]

MOPTS = ["mop_z", "mop_r", "mop_n", "mop_str", "mop_d", "mop_S", "mop_v",
         "mop_b", "mop_f", "mop_l", "mop_a", "mop_h", "mop_c", "mop_fn",
         "mop_p", "mop_sc"]


class Native(object):
    VALUES = {
        720: {
            "magic": 0x00DEC0DE00000003,
            "ui_broadcast": 7,
            "hx_mop_t_print": 260,
            "hx_minsn_t_print": 316,
            "hx_mblock_t_print": 338,
            "hx_mbl_array_t_print": 369,
            "hx_gen_microcode": 506,
            "offsetof_mbl_array_t_qty": (52, 64),
            "offsetof_mbl_array_t_natural": (464, 560),
            "offsetof_mblock_t_head": (40, 48),
            "offsetof_mblock_t_succset": (352, 368),
            "offsetof_minsn_t_opcode": (0, 0),
            "offsetof_minsn_t_next": (8, 8),
            "offsetof_minsn_t_l": (32, 32),
            "offsetof_minsn_t_r": (48, 48),
            "offsetof_minsn_t_d": (64, 64),
            "offsetof_mop_t_t": (0, 0),
            "offsetof_mop_t_union": (8, 8),
            "offsetof_mcallinfo_t_args": (24, 24),
            "sizeof_mcallarg_t": (64, 72),
            "offsetof_mop_pair_t_lop": (0, 0),
            "offsetof_mop_pair_t_hop": (16, 16),
        }
    }

    @staticmethod
    def get_library():
        dllname = "ida64" if ida_idaapi.__EA64__ else "ida"
        if sys.platform == "win32":
            dllname, dlltype = dllname + ".dll", ctypes.windll
        elif sys.platform == "linux2":
            dllname, dlltype = "lib" + dllname + ".so", ctypes.cdll
        elif sys.platform == "darwin":
            dllname, dlltype = "lib" + dllname + ".dylib", ctypes.cdll
        return dlltype[os.path.join(ida_diskio.idadir(None), dllname)]

    _cfg, _lib, _dsp, _rch = None, None, None, None

    @classmethod
    def init(cls):
        if ida_hexrays.init_hexrays_plugin():
            version = ida_pro.IDA_SDK_VERSION
            if version in Native.VALUES:
                cls._cfg = Native.VALUES[version]
                cls._lib = Native.get_library()
                cls._dsp = cls.get_dispatcher()
                cls._rch = 1 if ida_idaapi.__EA64__ else 0
                return True
        return False

    @classmethod
    def get_dispatcher(cls):
        callui = ctypes.c_void_p.in_dll(cls._lib, "callui")

        def broadcast(magic, *args):
            func_type = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_int,
                                         ctypes.c_ulonglong,
                                         ctypes.POINTER(ctypes.c_void_p))
            func_code = cls._cfg["ui_broadcast"]
            return func_type(callui.value)(func_code, magic, *args)

        hexdsp = ctypes.c_void_p()
        broadcast(cls._cfg["magic"], ctypes.byref(hexdsp))
        return hexdsp

    @classmethod
    def term(cls):
        return ida_hexrays.term_hexrays_plugin()

    class qvector(ctypes.Structure):
        _fields_ = [("array", ctypes.c_void_p),
                    ("n", ctypes.c_size_t),
                    ("alloc", ctypes.c_size_t)]

    @classmethod
    def qvector_str(cls, v):
        return "" if v.n == 0 else ctypes.cast(v.array, ctypes.c_char_p).value

    @classmethod
    def gen_microcode(cls, fn, hf, retlist, flags, reqmat):
        class mba_ranges_t(ctypes.Structure):
            _fields_ = [("pfn", ctypes.c_void_p),
                        ("ranges", cls.qvector)]

        fn = ctypes.c_void_p(int(fn.this))
        mbr = mba_ranges_t()
        mbr.pfn = fn
        mbr.ranges = cls.qvector()
        mbr = ctypes.c_void_p(ctypes.addressof(mbr))
        hf = ctypes.c_void_p(int(hf.this))
        retlist = ctypes.c_void_p(retlist)

        func_type = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_int,
                                     ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_void_p, ctypes.c_int,
                                     ctypes.c_int)
        func_code = cls._cfg["hx_gen_microcode"]
        return func_type(cls._dsp.value)(func_code,
                                         mbr, hf, retlist, flags, reqmat)

    @classmethod
    def mbl_array_t_print(cls, mba, vp):
        vp = ctypes.c_void_p(int(vp.this))
        func_type = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_void_p,
                                     ctypes.c_void_p)
        func_code = cls._cfg["hx_mbl_array_t_print"]
        return func_type(cls._dsp.value)(func_code, mba, vp)

    @classmethod
    def mbl_array_t_qty(cls, mba):
        offset = cls._cfg["offsetof_mbl_array_t_qty"][cls._rch]
        return ctypes.c_int.from_address(mba + offset)

    @classmethod
    def mbl_array_t_get_mblock(cls, mba, n):
        offset = cls._cfg["offsetof_mbl_array_t_natural"][cls._rch]
        qty = cls.mbl_array_t_qty(mba).value
        field_type = ctypes.POINTER(ctypes.c_void_p * qty)
        return field_type.from_address(mba + offset).contents[n]

    @classmethod
    def mblock_t_succset(cls, mblock):
        offset = cls._cfg["offsetof_mblock_t_succset"][cls._rch]
        succset = cls.qvector.from_address(mblock + offset)
        if succset.n > 0:
            array = (ctypes.c_int * succset.n).from_address(succset.array)
            for i in range(succset.n):
                yield array[i]

    @classmethod
    def mblock_t_print(cls, mblock, vp):
        vp = ctypes.c_void_p(int(vp.this))
        func_type = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_void_p,
                                     ctypes.c_void_p)
        func_code = cls._cfg["hx_mblock_t_print"]
        return func_type(cls._dsp.value)(func_code, mblock, vp)

    @classmethod
    def mblock_t_get_minsn(cls, mblock, serial):
        offset = cls._cfg["offsetof_mblock_t_head"][cls._rch]
        minsn = ctypes.c_void_p.from_address(mblock + offset)
        for i in range(serial):
            if not minsn:
                break
            offset = cls._cfg["offsetof_minsn_t_next"][cls._rch]
            minsn = ctypes.c_void_p.from_address(minsn.value + offset)
        return minsn

    @classmethod
    def minsn_t_opcode(cls, minsn):
        offset = cls._cfg["offsetof_minsn_t_opcode"][cls._rch]
        return ctypes.c_int.from_address(minsn.value + offset)

    @classmethod
    def minsn_t_l(cls, minsn):
        offset = cls._cfg["offsetof_minsn_t_l"][cls._rch]
        return ctypes.c_void_p(minsn.value + offset)

    @classmethod
    def minsn_t_r(cls, minsn):
        offset = cls._cfg["offsetof_minsn_t_r"][cls._rch]
        return ctypes.c_void_p(minsn.value + offset)

    @classmethod
    def minsn_t_d(cls, minsn):
        offset = cls._cfg["offsetof_minsn_t_d"][cls._rch]
        return ctypes.c_void_p(minsn.value + offset)

    @classmethod
    def minsn_t_print(cls, minsn, shins_flags=ida_hexrays.SHINS_SHORT |
                                              ida_hexrays.SHINS_VALNUM):
        py_vout = cls.qvector()
        vout = ctypes.cast(ctypes.addressof(py_vout), ctypes.c_void_p)
        func_type = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_void_p,
                                     ctypes.c_void_p, ctypes.c_int)
        func_code = cls._cfg["hx_minsn_t_print"]
        func_type(cls._dsp.value)(func_code, minsn, vout, shins_flags)
        return cls.qvector_str(py_vout)

    @classmethod
    def mop_t_t(cls, mop):
        offset = cls._cfg["offsetof_mop_t_t"][cls._rch]
        return ctypes.c_uint8.from_address(mop.value + offset)

    @classmethod
    def mop_t_union(cls, mop):
        offset = cls._cfg["offsetof_mop_t_union"][cls._rch]
        return ctypes.c_void_p.from_address(mop.value + offset)

    @classmethod
    def mop_t_print(cls, mop, shins_flags=ida_hexrays.SHINS_SHORT |
                                          ida_hexrays.SHINS_VALNUM):
        py_vout = cls.qvector()
        vout = ctypes.cast(ctypes.addressof(py_vout), ctypes.c_void_p)
        func_type = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_void_p,
                                     ctypes.c_void_p, ctypes.c_int)
        func_code = cls._cfg["hx_mop_t_print"]
        func_type(cls._dsp.value)(func_code, mop, vout, shins_flags)
        return cls.qvector_str(py_vout)

    @classmethod
    def mcallinfo_t_args(cls, f):
        offset = cls._cfg["offsetof_mcallinfo_t_args"][cls._rch]
        return ctypes.c_void_p(f.value + offset)

    @classmethod
    def mcallargs_t_iter(cls, args):
        args = ctypes.cast(args, ctypes.POINTER(cls.qvector)).contents
        for i in range(args.n):
            size = cls._cfg["sizeof_mcallarg_t"][cls._rch]
            yield ctypes.c_void_p(args.array + size * i)

    @classmethod
    def mop_pair_t_lop(cls, pair):
        offset = cls._cfg["offsetof_mop_pair_t_lop"][cls._rch]
        return ctypes.c_void_p(pair.value + offset)

    @classmethod
    def mop_pair_t_hop(cls, pair):
        offset = cls._cfg["offsetof_mop_pair_t_hop"][cls._rch]
        return ctypes.c_void_p(pair.value + offset)


class MCInsnView(ida_graph.GraphViewer):
    def __init__(self, mba, func, mmat, block, serial):
        title = "MCInsn View - %s at %s / %d.%d" % (func, mmat, block, serial)
        ida_graph.GraphViewer.__init__(self, title, True)

        self.mblock = Native.mbl_array_t_get_mblock(mba, block)
        self.minsn = Native.mblock_t_get_minsn(self.mblock, serial)

    def _insert_minsn(self, minsn):
        text = MCODES[Native.minsn_t_opcode(minsn).value]
        text += '\n' + Native.minsn_t_print(minsn)
        node_id = self.AddNode(text)

        self._insert_mop(Native.minsn_t_l(minsn), node_id)
        self._insert_mop(Native.minsn_t_r(minsn), node_id)
        self._insert_mop(Native.minsn_t_d(minsn), node_id)
        return node_id

    def _insert_mop(self, mop, parent):
        t = Native.mop_t_t(mop).value
        if t == 0:
            return -1

        text = MOPTS[t] + '\n' + Native.mop_t_print(mop)
        node_id = self.AddNode(text)
        self.AddEdge(parent, node_id)

        if t == MOPTS.index("mop_d"):
            dst = self._insert_minsn(Native.mop_t_union(mop))
            self.AddEdge(node_id, dst)
        elif t == MOPTS.index("mop_f"):
            f = Native.mop_t_union(mop)
            args = Native.mcallinfo_t_args(f)
            for arg in Native.mcallargs_t_iter(args):
                self._insert_mop(arg, node_id)
        elif t == MOPTS.index("mop_a"):
            self._insert_mop(Native.mop_t_union(mop), node_id)
        elif t == MOPTS.index("mop_p"):
            pair = Native.mop_t_union(mop)
            self._insert_mop(Native.mop_pair_t_lop(pair), node_id)
            self._insert_mop(Native.mop_pair_t_hop(pair), node_id)
        return node_id

    def OnRefresh(self):
        self.Clear()
        self._insert_minsn(self.minsn)
        return True

    def OnGetText(self, node_id):
        return self._nodes[node_id]


class MCGraphView(ida_graph.GraphViewer):
    def __init__(self, mba, func, mmat):
        title = "MCGraph View - %s at %s" % (func, mmat)
        ida_graph.GraphViewer.__init__(self, title, True)
        self._mba = mba

    def OnRefresh(self):
        self.Clear()
        qty = Native.mbl_array_t_qty(self._mba).value
        for src in range(qty):
            self.AddNode(src)
        for src in range(qty):
            mblock = Native.mbl_array_t_get_mblock(self._mba, src)
            for dest in Native.mblock_t_succset(mblock):
                self.AddEdge(src, dest)
        return True

    def OnGetText(self, node):
        mblock = Native.mbl_array_t_get_mblock(self._mba, node)
        vp = ida_hexrays.qstring_printer_t(None, True)
        Native.mblock_t_print(mblock, vp)
        return vp.s


class MCTextView(ida_kernwin.simplecustviewer_t):
    def __init__(self, mba, func, mmat):
        ida_kernwin.simplecustviewer_t.__init__(self)
        self._mba = mba
        self._func = func
        self._mmat = mmat
        title = "MCText View - %s at %s" % (func, mmat)
        self.Create(title)

        vp = ida_hexrays.qstring_printer_t(None, True)
        Native.mbl_array_t_print(mba, vp)
        for line in vp.s.split('\n'):
            self.AddLine(line)

    def OnKeydown(self, vkey, shift):
        if shift == 0 and vkey == ord("G"):
            MCGraphView(self._mba, self._func, self._mmat).Show()
            return True
        elif shift == 0 and vkey == ord("I"):
            widget = self.GetWidget()
            line = ida_kernwin.get_custom_viewer_curline(widget, False)
            line = ida_lines.tag_remove(line)
            if '.' in line:
                block, serial = line.split('.')[:2]
                serial = serial.strip().split(' ')[0]
                MCInsnView(self._mba, self._func, self._mmat,
                           int(block), int(serial)).Show()
            return True
        return False


class MCExplorer(ida_idaapi.plugin_t):
    flags = 0
    comment = "Microcode Explorer"
    help = ""
    wanted_name = "MCExplorer"
    wanted_hotkey = "Ctrl+Shift+M"

    @staticmethod
    def ask_desired_maturity():
        class MaturityForm(ida_kernwin.Form):
            def __init__(self):
                ctrl = ida_kernwin.Form.DropdownListControl(LEVELS)
                form = """Select maturity level
                 <Select maturity level:{ctrl}>"""
                ida_kernwin.Form.__init__(self, form, {"ctrl": ctrl})

        form = MaturityForm()
        form, args = form.Compile()
        ok = form.Execute()
        mmat = 0
        if ok == 1:
            mmat = form.ctrl.value + 1
        form.Free()
        return mmat

    def init(self):
        if not Native.init():
            return ida_idaapi.PLUGIN_SKIP
        print("[MCExplorer] Plugin initialized")
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        Native.term()
        print("[MCExplorer] Plugin terminated")

    def run(self, _):
        fn = ida_funcs.get_func(ida_kernwin.get_screen_ea())
        if fn is None:
            ida_kernwin.warning("Please position the cursor within a function")
            return True

        mmat = MCExplorer.ask_desired_maturity()
        if mmat == 0:
            return True

        hf = ida_hexrays.hexrays_failure_t()
        mba = Native.gen_microcode(fn, hf, None, 0, mmat)
        if not mba:
            return True

        fn_name = ida_funcs.get_func_name(fn.start_ea)
        mmat_name = LEVELS[mmat - 1]
        MCTextView(mba, fn_name, mmat_name).Show()
        return True


def PLUGIN_ENTRY():
    return MCExplorer()
