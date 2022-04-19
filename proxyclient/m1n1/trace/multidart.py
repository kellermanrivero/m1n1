# SPDX-License-Identifier: MIT

from ..hw.dart import *
from ..hv import TraceMode
from ..utils import *
from . import ADTDevTracer

MAX_SID = 16
class MDARTTracer(ADTDevTracer):
    RELOAD_DEPS = [DART]

    DEFAULT_MODE = TraceMode.ASYNC

    REGMAPS = [DARTRegs, DARTRegs, DARTRegs, DARTRegs, DARTRegs, DARTRegs]
    NAMES = ["dart0", "dart1", "dart2", "smmu0", "smmu1", "dapf0"]
    PREFIXES = ["dart0", "dart1", "dart2", "smmu0", "smmu1", "dapf0"]

    @classmethod
    def _reloadcls(cls, force=False):
        global DART
        DART = DART._reloadcls(force)
        return super()._reloadcls()

    def start(self):
        super().start()

        self.regs =[
            (self.dart0, DART(self.hv.iface, self.dart0, compat=self.dev.compatible[0])),
            (self.dart1, DART(self.hv.iface, self.dart1, compat=self.dev.compatible[0])),
            (self.dart2, DART(self.hv.iface, self.dart2, compat=self.dev.compatible[0])),
            (self.smmu0, DART(self.hv.iface, self.smmu0, compat=self.dev.compatible[0])),
            (self.smmu1, DART(self.hv.iface, self.smmu1, compat=self.dev.compatible[0])),
            (self.dapf0, DART(self.hv.iface, self.dapf0, compat=self.dev.compatible[0])),
        ]

        #prime cache
        for _, tuple in enumerate(self.regs):
            regmap = tuple[0]
            for i in range(MAX_SID):
                regmap.TCR[i].val
                for j in range(4):
                    regmap.TTBR[i, j].val
            regmap.ENABLED_STREAMS.val

    def w_STREAM_COMMAND(self, evt, stream_command):
        if stream_command.INVALIDATE:
            for _, tuple in enumerate(self.regs):
                regmap = tuple[0]
                dart = tuple[1]
                name, index, ccls = regmap.lookup_addr(evt.addr)
                if name is not None: 
                    self.log(f"Invalidate Stream: {regmap.cached.STREAM_SELECT.reg}")
                    dart.invalidate_cache()
                    return
    
    def ioread(self, stream, base, size, idx=None):
        if size == 0:
            return b""

        if idx is not None:
            self.log('Dumping contents of DART:')
            chexdump(self.regs[idx][1].ioread(stream, base, size))
        else:
            self.log('Dumping contents of DART0:')
            chexdump(self.regs[0][1].ioread(stream, base, size))

            self.log('Dumping contents of DART1:')
            chexdump(self.regs[1][1].ioread(stream, base, size))

            self.log('Dumping contents of DART2:')
            chexdump(self.regs[2][1].ioread(stream, base, size))

