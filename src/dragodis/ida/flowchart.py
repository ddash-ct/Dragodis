
from __future__ import annotations
from typing import Iterable, TYPE_CHECKING

from dragodis.interface import Flowchart, BasicBlock, FlowType
from dragodis.utils import genproperty

if TYPE_CHECKING:
    from dragodis.ida.flat import IDAFlatAPI
    import ida_gdl


class IDABasicBlock(BasicBlock):

    def __init__(self, ida: IDAFlatAPI, block: "ida_gdl.BasicBlock"):
        super().__init__(ida)
        self._ida = ida
        self._block = block

    @property
    def start(self) -> int:
        return self._block.start_ea

    @property
    def end(self) -> int:
        return self._block.end_ea

    @property
    def flow_type(self) -> FlowType:
        # IDA leaves self._block.type much to be desired,
        # so we'll just look at the last instruction instead.
        for line in self.lines(reverse=True):
            return line.instruction.flow_type
        raise ValueError(f"Block at {hex(self.start)} has no instructions.")

    @property
    def flowchart(self) -> "IDAFlowchart":
        return IDAFlowchart(self._ida, self._block._fc)

    @genproperty
    def blocks_to(self) -> Iterable["IDABasicBlock"]:
        for block in self._block.preds():
            # Discovered glitch in IDA, where an "empty" block is provided.
            # This block is incorrect and not part of the flowchart.
            if block.start_ea == block.end_ea:
                continue
            yield IDABasicBlock(self._ida, block)

    @genproperty
    def blocks_from(self) -> Iterable["IDABasicBlock"]:
        for block in self._block.succs():
            # Discovered glitch in IDA, where an "empty" block is provided.
            # This block is incorrect and not part of the flowchart.
            if block.start_ea == block.end_ea:
                continue
            yield IDABasicBlock(self._ida, block)


class IDAFlowchart(Flowchart):

    def __init__(self, ida: IDAFlatAPI, flowchart: "ida_gdl.FlowChart"):
        self._ida = ida
        self._flowchart = flowchart

    def __len__(self) -> int:
        return self._flowchart.size

    @genproperty
    def blocks(self) -> Iterable[IDABasicBlock]:
        for block in self._flowchart:
            # Discovered glitch in IDA, where an "empty" block is provided.
            # This block is incorrect and not part of the flowchart.
            if block.start_ea == block.end_ea:
                continue
            yield IDABasicBlock(self._ida, block)
