from __future__ import annotations
from typing import Iterable, TYPE_CHECKING

from visgraph.graphcore import HierGraph
from vivisect.codegraph import FuncBlockGraph

from dragodis.interface import Flowchart, BasicBlock, FlowType
from dragodis.utils import genproperty
from dragodis.vivisect.viv import GraphNode, GraphEdge, Location

if TYPE_CHECKING:
    from dragodis.vivisect.flat import VivisectFlatAPI


class VivisectBasicBlock(BasicBlock):

    def __init__(self, api: VivisectFlatAPI, graph: HierGraph, node: GraphNode):
        super().__init__(api)
        self._graph = graph
        self._node = node

    @property
    def start(self) -> int:
        # code block address + size
        return self._node.props["cbva"]

    @property
    def _last_address(self) -> int:
        """Start address for last instruction of the block."""
        location = Location(*self._api._workspace.getLocation(self.end - 1))
        return location.va

    @property
    def end(self) -> int:
        # code block address + size
        return self._node.props["cbva"] + self._node.props["cbsize"]

    @property
    def flow_type(self) -> FlowType:
        return self._api.get_instruction(self._last_address).flow_type

    @property
    def flowchart(self) -> VivisectFlowchart:
        return VivisectFlowchart(self._api, self._graph)

    @genproperty
    def blocks_to(self) -> Iterable[VivisectBasicBlock]:
        for edge in self._graph.getRefsTo(self._node):
            edge = GraphEdge(*edge)
            node = GraphNode(*self._graph.getNode(edge.node1))
            yield VivisectBasicBlock(self._api, self._graph, node)

    @genproperty
    def blocks_from(self) -> Iterable[VivisectBasicBlock]:
        for edge in self._graph.getRefsFrom(self._node):
            edge = GraphEdge(*edge)
            node = GraphNode(*self._graph.getNode(edge.node2))
            yield VivisectBasicBlock(self._api, self._graph, node)


class VivisectFlowchart(Flowchart):

    def __init__(self, vivisect: VivisectFlatAPI, graph: HierGraph):
        self._vivisect = vivisect
        self._graph = graph

    @genproperty
    def blocks(self) -> Iterable[VivisectBasicBlock]:
        for node in sorted(self._graph.getNodes()):
            node = GraphNode(*node)
            yield VivisectBasicBlock(self._vivisect, self._graph, node)
