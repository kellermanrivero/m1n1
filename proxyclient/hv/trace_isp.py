# SPDX-License-Identifier: MIT
from collections import namedtuple
from m1n1 import asm
from m1n1.trace import Tracer
from m1n1.utils import *
from m1n1.proxy import *
from m1n1.sysreg import *
from m1n1.proxyutils import RegMonitor
from m1n1.trace.asc import *
from m1n1.fw.asc import *
from m1n1.trace.dart import DARTTracer
from m1n1.trace.multidart import MDARTTracer
from m1n1.trace.i2c import I2CTracer
from m1n1.gpiola import GPIOLogicAnalyzer
from m1n1.hw.dart import DART, DARTRegs

I2CTracer = I2CTracer._reloadcls()
ASCTracer = ASCTracer._reloadcls()
DARTTracer = DARTTracer._reloadcls()
MDARTTracer = MDARTTracer._reloadcls()

## Bus Base Addresses
## 0x22a000000
## 0x23b700000
## 0x23c260000
## 0x23c280000
## 0x23c290000
## Dart Addresses
## 0x22c0e8000 (DART           , idx = 0)
## 0x22c0ec000 (DAPF or SMMU?  , idx = 5)
## 0x22c0f0000 (SMMU           , idx = 3)
## 0x22c0f4000 (DART           , idx = 1)
## 0x22c0f8000 (SMMU           , idx = 4)
## 0x22c0fc000 (DART           , idx = 2)

## chexdump(isp_dart_tracer.regs[0][1].ioread(0, 0x9228000, 0x3fd0))
## chexdump(isp_dart_tracer.regs[0][1].ioread(0, 0x1824000, 35651584))
## chexdump(isp_dart_tracer.regs[0][1].ioread(0, 0x1804000, 16536))
## chexdump(isp_dart_tracer.regs[1][1].ioread(0, 0x3A28000, 0x8000)) 
## chexdump(isp_dart_tracer.regs[1][1].ioread(0, 0x3A28000, 0x18000)) --> SYSLOG

class ISPCommand:
    def __init__(self, message):
        value, u0, u1 = struct.unpack('<3q40x', message.data)
        self.message = message
        self.tracer = message.channel.tracer
        self.channel = message.channel
        self.raw_value = value
        self.value = value & 0xFFFFFFFFFFFFFFFC
        self.arg0 = u0
        self.arg1 = u1

    def dump(self):
        self.log(f"[CMD Value: {hex(self.value)}, U0: {hex(self.arg0)}, U1: {hex(self.arg1)}]")

    def read_iova(self, address, length):
        return self.tracer.dart.ioread(0, address, length)

    def log(self, message):
        self.tracer.log(f"[{self.channel.name}]({self.message.index}): {message}")

class ISPTerminalCommand(ISPCommand):
    def __init__(self, message):
        super().__init__(message)
        self.buffer_address = self.value
        self.buffer_length = self.arg0
        if self.buffer_address != 0:
            self.buffer_message = self.read_iova(self.buffer_address, self.buffer_length)
        else:
            self.buffer_message = None

    def dump(self):
        if self.buffer_address != 0:
            self.log(f"[A: {hex(self.buffer_address)}, L: {hex(self.buffer_length)}, ISPCPU: {self.buffer_message.decode()}]")
        else:
            self.log(f"[A: {hex(self.buffer_address)}, L: {hex(self.buffer_length)}]")

class ISPIOCommand(ISPCommand):
    def __init__(self, message):
        super().__init__(message)
        self.iova = self.value
        if self.iova != 0:
            contents = self.read_iova(self.iova, 0x8)
            self.contents = int.from_bytes(contents, byteorder="little")
        else:
            self.contents = None

    def dump(self):
        if self.iova != 0:
            chexdump(self.read_iova(self.iova, 0x100))
            self.log(f"[IO Addr: {hex(self.iova)} -> Opcode: {hex(self.contents >> 32)}]")

class ISPSharedMallocCommand(ISPCommand):
    def __init__(self, message):
        super().__init__(message)
        self.address = self.value
        self.size = self.arg0
        self.type = self.arg1 #.to_bytes(8, byteorder="little")

    def dump(self):
        if self.address is 0:
            self.log(f"[FW Malloc, Length: {hex(self.size)}, Type: {hex(self.type)}]")
        else:
            self.log(f"[FW Free, Address: {hex(self.value)}, Length: {hex(self.size)}, Type: {hex(self.type)})]")


class ISPChannel:
    def __init__(self, tracer, name, _type, source, number_of_entries, entry_size, address):
        self.tracer = tracer
        self.name = str(name, "ascii").rstrip('\x00')
        self.source = source
        self.type = _type
        self.number_of_entries = number_of_entries
        self.entry_size = entry_size
        self.size = self.number_of_entries * self.entry_size
        self.address = address
        self.entry_index = 0
    
    def get_commands(self):
        commands = []
        message = self.get_message()
        if message:
            command = message.get_command()
            if command:
                commands.append(command)
        return commands

    def dump(self):
        s = f"[{self.name}] Channel messages: \n"
        for entry in self.get_all_messages():
            s = s + "\t" + entry.dump() + "\n"
        self.tracer.log(s)

    def get_message(self):
        idx = 0
        entry = None
        channel_data = self.tracer.dart.ioread(0, self.address, self.size)
        for i in range(0, self.size, self.entry_size):
            if idx == self.entry_index:
                entry_data = channel_data[i: i + self.entry_size]
                entry = ISPChannelMessage(idx, self, entry_data)
                self.entry_index = self.entry_index + 1
                break
            idx = idx + 1
        
        if self.entry_index >= self.number_of_entries:
            self.entry_index = 0
        return entry

    def get_all_messages(self):
        entries = []
        channel_data = self.tracer.dart.ioread(0, self.address, self.size)
        for i in range(0, self.size, self.entry_size):
            entry_data = channel_data[i: i + self.entry_size]
            entry = ISPChannelMessage(i / self.entry_size, self, entry_data)
            entries.append(entry)
        return entries
        
    def __str__(self):
        return f"[CH - {str(self.name)}] (src = {self.source!s}, type = {self.type!s}, size = {self.number_of_entries!s}, iova = {hex(self.address)!s})"

    
class ISPChannelMessage:
    def __init__(self, index, channel, data):
        self.index = index
        self.channel = channel
        self.data = data
    
    def get_command(self):
        cmd_value = struct.unpack('<1q56x', self.data)[0]
        is_type_zero = 1 if self.channel.type == 0 else 0
        #if (cmd_value & 1) == (is_type_zero & 1):
        if self.channel.name == "TERMINAL":
            return ISPTerminalCommand(self)
        elif self.channel.name == "IO":
            return ISPIOCommand(self)
        elif self.channel.name == "SHAREDMALLOC":
            return ISPSharedMallocCommand(self)
        else:
            return None
        # else:
        #     self.channel.tracer.log(f"[{self.channel.name}] Warning, invalid command. Cmd value: {cmd_value}")
        #     return None
    
    def dump(self, raw = None):
        s = "ISP Message: {"
        if raw:
            s = "\n" + chexdump(self.data) + "\n"
        else:
            idx = 0
            for i in struct.unpack('<8q', self.data):
                s = s + f"Arg{idx}: {hex(i)}, " 
                idx = idx + 1
        
        s = s + "}"
        return s  

class ISP_REVISION(Register32):
    REVISION = 15, 0

class ISP_PMU(Register32):
    STATUS = 7, 0
    OTHER = 63, 8

class ISP_PMU_SPECIAL_STATUS(Register32):
    STATUS = 7, 0
    OTHER = 63, 8

class ISPRegs(RegMap):
    ISP_CPU_CONTROL         = 0x0000, R_CPU_CONTROL
    ISP_CPU_STATUS          = 0x0004, Register32
    ISP_REVISION            = 0x1800000, ISP_REVISION
    ISP_POWER_UNKNOWN       = 0x20e0080, Register32
    ISP_IRQ_INTERRUPT       = 0x2104000, Register32
    ISP_IRQ_INTERRUPT_2     = 0x2104004, Register32
    ISP_SENSOR_REF_CLOCK    = irange(0x2104190, 3, 4), Register32
    ISP_GPR0                = 0x2104170, Register32
    ISP_GPR1                = 0x2104174, Register32
    ISP_GPR2                = 0x2104178, Register32
    ISP_GPR3                = 0x210417c, Register32
    ISP_GPR4                = 0x2104180, Register32
    ISP_GPR5                = 0x2104184, Register32
    ISP_GPR6                = 0x2104188, Register32
    ISP_GPR7                = 0x210418c, Register32

    ISP_DOORBELL_RING0      = 0x21043f0, Register32
    ISP_IRQ_INTERRUPT_ACK   = 0x21043fc, Register32

    ISP_SMBUS_REG_MTXFIFO   = irange(0x2110000, 4, 0x1000), Register32
    ISP_SMBUS_REG_MRXFIFO   = irange(0x2110004, 4, 0x1000), Register32
    ISP_SMBUS_REG_UNK_1     = irange(0x2110008, 4, 0x1000), Register32
    ISP_SMBUS_REG_UNK_2     = irange(0x211000c, 4, 0x1000), Register32
    ISP_SMBUS_REG_UNK_3     = irange(0x2110010, 4, 0x1000), Register32
    ISP_SMBUS_REG_SMSTA     = irange(0x2110014, 4, 0x1000), Register32
    ISP_SMBUS_REG_UNK_4     = irange(0x2110018, 4, 0x1000), Register32
    ISP_SMBUS_REG_CTL       = irange(0x211001c, 4, 0x1000), Register32
    ISP_SMBUS_REG_UNK_5     = irange(0x2110020, 4, 0x1000), Register32
    ISP_SMBUS_REG_UNK_6     = irange(0x2110024, 4, 0x1000), Register32
    ISP_SMBUS_REG_REV       = irange(0x2110028, 4, 0x1000), Register32
    ISP_SMBUS_REG_UNK_7     = irange(0x211002c, 4, 0x1000), Register32
    ISP_SMBUS_REG_UNK_8     = irange(0x2110030, 4, 0x1000), Register32
    ISP_SMBUS_REG_UNK_9     = irange(0x2110034, 4, 0x1000), Register32
    ISP_SMBUS_REG_UNK_A     = irange(0x2110038, 4, 0x1000), Register32
    ISP_SMBUS_REG_UNK_B     = irange(0x211003c, 4, 0x1000), Register32

    ISP_DPE_REG_UNK1        = 0x2504000, Register32
    ISP_DPE_REG_UNK2        = 0x2508000, Register32

    ISP_CPU_BUFFER          = 0x1050000, Register32

    ISP_SPMI0_REGISTER_BASE = 0x2900000, Register32
    ISP_SPMI1_REGISTER_BASE = 0x2920000, Register32
    ISP_SPMI2_REGISTER_BASE = 0x2940000, Register32

class PSReg(RegMap):
    PMU_UNKNOWN0           = 0x4000, ISP_PMU
    PMU_UNKNOWN1           = 0x4008, ISP_PMU
    PMU_UNKNOWN2           = 0x4010, ISP_PMU
    PMU_UNKNOWN3           = 0x4018, ISP_PMU
    PMU_UNKNOWN4           = 0x4020, ISP_PMU
    PMU_UNKNOWN5           = 0x4028, ISP_PMU
    PMU_UNKNOWN6           = 0x4030, ISP_PMU
    PMU_UNKNOWN7           = 0x4038, ISP_PMU
    PMU_UNKNOWN8           = 0x4040, ISP_PMU
    PMU_UNKNOWN9           = 0x4048, ISP_PMU
    PMU_UNKNOWNA           = 0x4050, ISP_PMU
    PMU_UNKNOWNB           = 0x4058, ISP_PMU
    PMU_SPECIAL_STATUS     = 0x4060, ISP_PMU_SPECIAL_STATUS
    CLOCK_TICK_LOW         = 0x34004, Register32
    CLOCK_TICK_HIGH        = 0x34008, Register32
    RT_BANDWIDTH_SCRATCH1  = 0x38014, Register32
    RT_BANDWIDTH_SCRATCH2  = 0x38018, Register32

class SPMIReg(RegMap):
    SPMI_UNKNOWN0           = 0x28, Register32
    SPMI_UNKNOWN1           = 0x40, Register32
    SPMI_UNKNOWN2           = 0x90, Register32
    SPMI_UNKNOWN3           = 0x80a0, Register32
    SPMI_UNKNOWN4           = 0x80a4, Register32

class ISPTracer(ADTDevTracer):
    
    DEFAULT_MODE = TraceMode.SYNC

    REGMAPS = [ISPRegs, None, None, None, None]
    NAMES = ["isp", "ps", "spmi0", "spmi1", "spmi2"]

    ENDPOINTS = {
        0: Management,
        #1: CrashLog,
        2: Syslog,
        #3: KDebug,
        #4: IOReporting,
    }

    def __init__(self, hv, dev_path, dart_dev_path, verbose):
        super().__init__(hv, dev_path, verbose)

        p.pmgr_adt_clocks_enable("/arm-io/dart-isp")
        self.isp_dart_tracer = MDARTTracer(hv, "/arm-io/dart-isp", verbose=3)
        self.isp_dart_tracer.start()

        # Use DART0 by default
        self.dart = self.isp_dart_tracer.regs[0][1]

        self.ignored_ranges = [
            # -----------------------------------------------------------------
            # The following memory addresses fall into ERROR/LOG address range.
            # 0x23b700000 -  0x23b78C000  < -- Used by PERF, LOG and ERROR stuff (reporting?)
            # ## System clock counter (24 mhz)
            (0x23b734004, 4), 
            (0x23b734008, 4), 
            # ## Noisy memory addresses that are always zero
            (0x23b734868, 4), 
            (0x23b73486c, 4), 
            (0x23b734b38, 4), 
            (0x23b734b3c, 4), 
            (0x23b734b58, 4), 
            (0x23b734b5c, 4), 
            (0x23b734bd8, 4),
            (0x23b734bdc, 4),
            (0x23b734c18, 4),
            (0x23b734c1c, 4),
            (0x23b778128, 4), 
            (0x23b77812c, 4),
            (0x23b77c128, 4),
            (0x23b77c12c, 4),
            # # Noisy memory addresses that change value
            (0x23b700248, 4), 
            (0x23b700258, 4), 
            (0x23b7003f8, 4), 
            (0x23b700470, 4),
            # # ECPU/PCPU state report
            (0x23b738004, 4), # ecpu state report
            (0x23b738008, 4), # pcpu state report
            # -----------------------------------------------------------------
        ]

    def w_OUTBOX_CTRL(self, evt, val):
        self.log(f"OUTBOX_CTRL = {val!s}")

    def r_ISP_GPR0(self, evt, val):
        # I have no idea how many channels may be available in other platforms
        # but, at least for M1 I know they are seven (7), so using 64 as safe value here
        if val.value == 0x8042006:
            self.log(f"ISP_GPR0 = ACK")
        elif val.value < 64: 
            self.log(f"ISP_IPC_CHANNELS = {val!s}")
            self.number_of_channels = val.value
            self.channel_table_entry_length = 0x100
        elif val.value > 0:
            self.log(f"ISP_IPC_CHANNEL_TABLE_IOVA = {val!s}")
            self.channel_table_iova = val.value
            self.channel_list = []
            if self.dart:
                ch_tbl = self.dart.ioread(0, val.value & 0xFFFFFFFF, self.number_of_channels * self.channel_table_entry_length)
                self.log("======== CHANNEL TABLE ========")
                ch_idx = 0
                for ch_offset in range(0, self.number_of_channels * self.channel_table_entry_length, self.channel_table_entry_length):
                    ch_entry_bytes =  ch_tbl[ch_offset: ch_offset + self.channel_table_entry_length]
                    # 0x00 => Channel Name
                    # 0x40 => Channel Type
                    # 0x44 => Channel Source
                    # 0x48 => Channel Size (or number of entries, each entry is 0x40 bytes)
                    # 0x50 => Channel Addr
                    ch_name, ch_type, ch_source, ch_size, ch_addr = struct.unpack('<32s32x2I2q168x', ch_entry_bytes) 
                    ch_entry = ISPChannel(self, ch_name, ch_type, ch_source, ch_size, 0x40, ch_addr)
                    self.channel_list.append(ch_entry)
                    self.log(f'{str(ch_entry)}')

    def r_ISP_IRQ_INTERRUPT(self, evt, val):
        irq_id = val.value
        cidx = 0
        for channel in self.channel_list:
            if (irq_id >> channel.type & 1) != 0:
                for cmd in channel.get_commands():
                    cmd.dump()
                    #self.dump_ipc_channel(cidx)
            cidx = cidx + 1 

    def w_ISP_DOORBELL_RING0(self, evt, val):
        value = val.value
        if value is 1:
            self.dump_ipc_channel(0)
        elif value is 2:
            self.dump_ipc_channel(1)
            self.dump_ipc_channel(2)
        elif value is 4:
            self.dump_ipc_channel(3)
        elif value is 8:
            self.dump_ipc_channel(4)
            self.dump_ipc_channel(5)
            self.dump_ipc_channel(6)
        pass

    def w_ISP_DOORBELL_RING1(self, evt, val):
        pass

    def w_ISP_GPR0(self, evt, val):
        self.log(f"ISP_GPR0 = ({val!s})")
        if val.value == 0x1812f80:
            if self.dart:
                self.init_struct = self.dart.ioread(0, val.value & 0xFFFFFFFF, 0x190)

    def w_ISP_IRQ_INTERRUPT(self, evt, val):
        self.log(f"IRQ_INTERRUPT = ({val!s}).")
        if val.value == 0xf:
            self.log(f"ISP Interrupts enabled")
            self.dump_ipc_channel(0)
            self.dump_ipc_channel(1)

    def w_INBOX_CTRL(self, evt, val):
        self.log(f"INBOX_CTRL = {val!s}")

    def w_CPU_CONTROL(self, evt, val):
        self.log(f"CPU_CONTROL = {val!s}")

    def w_INBOX1(self, evt, inbox1):
        inbox0 = self.asc.cached.INBOX0.reg
        if self.verbose >= 2:
            self.log(f"SEND: {inbox0.value:016x}:{inbox1.value:016x} " +
                    f"{inbox0.str_fields()} | {inbox1.str_fields()}")
        self.handle_msg(DIR.TX, inbox0, inbox1)

    def r_OUTBOX1(self, evt, outbox1):
        outbox0 = self.asc.cached.OUTBOX0.reg
        if self.verbose >= 2:
            self.log(f"RECV: {outbox0.value:016x}:{outbox1.value:016x} " +
                    f"{outbox0.str_fields()} | {outbox1.str_fields()}")
        self.handle_msg(DIR.RX, outbox0, outbox1)

    def init_state(self):
        self.state.ep = {}

    def handle_msg(self, direction, r0, r1):
        if r1.EP in self.epmap:
            if self.epmap[r1.EP].handle_msg(direction, r0, r1):
                return

        d = ">" if direction == DIR.TX else "<"
        self.log(f"{d}ep:{r1.EP:02x} {r0.value:016x} ({r0.str_fields()})")

    def ioread(self, dva, size):
        if self.dart:
            return self.dart.ioread(0, dva & 0xFFFFFFFF, size)
        else:
            return self.hv.iface.readmem(dva, size)

    def iowrite(self, dva, data):
        if self.dart:
            return self.dart.iowrite(0, dva & 0xFFFFFFFF, data)
        else:
            return self.hv.iface.writemem(dva, data)

    def dump_ipc_channel(self, idx = 0):
        if self.channel_list and len(self.channel_list) > 0:
            channel = self.channel_list[idx]
            channel.dump()

    def start(self):
        super().start()

        self.msgmap = {}
        for name in dir(self):
            i = getattr(self, name)
            if not callable(i) or not getattr(i, "is_message", False):
                continue
            self.msgmap[i.direction, i.endpoint, i.message] = getattr(self, name), name, i.regtype

        self.epmap = {}
        self.ep = EPContainer()
        for cls in type(self).mro():
            eps = getattr(cls, "ENDPOINTS", None)
            if eps is None:
                break
            for k, v in eps.items():
                if k in self.epmap:
                    continue
                ep = v(self, k)
                ep.dart = self.dart
                self.epmap[k] = ep
                if k in self.state.ep:
                    ep.state.__dict__.update(self.state.ep[k])
                self.state.ep[k] = ep.state.__dict__
                if getattr(self.ep, ep.name, None):
                    ep.name = f"{ep.name}{k:02x}"
                setattr(self.ep, ep.name, ep)
                ep.start()
        
        # Disable trace of memory regions 
        for addr, size in self.ignored_ranges:
            self.trace(addr, size, TraceMode.OFF)

class ANETracer(ASCTracer):
    pass

# p.pmgr_adt_clocks_enable("/arm-io/dart-ane")
# ane_dart_tracer = DARTTracer(hv, "/arm-io/dart-ane", verbose=3)
# ane_dart_tracer.start()

# ane_tracer = ANETracer(hv, "/arm-io/ane", verbose=3)
# ane_tracer.start(dart_tracer.dart)

hv.log('ISP: Registering ISP ASC tracer...')
isp_asc_tracer = ISPTracer(hv, "/arm-io/isp", "/arm-io/dart-isp", verbose=4)
isp_asc_tracer.start()