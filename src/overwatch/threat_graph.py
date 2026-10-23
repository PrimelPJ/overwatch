"""
Threat intelligence knowledge graph for modeling entity relationships.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from overwatch.models import IOC, ThreatActor


class NodeType(str, Enum):
    IOC = "ioc"
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"
    TECHNIQUE = "technique"
    TOOL = "tool"
    VULNERABILITY = "vulnerability"


class RelationType(str, Enum):
    USES = "uses"
    INDICATES = "indicates"
    ATTRIBUTED_TO = "attributed_to"
    TARGETS = "targets"
    MITIGATES = "mitigates"
    RELATED_TO = "related_to"
    PART_OF = "part_of"
    VARIANT_OF = "variant_of"


@dataclass
class GraphNode:
    node_id: str
    node_type: NodeType
    label: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    relation: RelationType
    confidence: float = 1.0
    attributes: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.source_id, self.target_id, self.relation.value)


@dataclass
class PageRankResult:
    node_id: str
    score: float
    node_type: NodeType
    label: str


@dataclass
class PathResult:
    source: str
    target: str
    path: List[str]
    edges: List[GraphEdge]
    total_confidence: float


class ThreatGraph:
    """
    Directed threat intelligence knowledge graph.

    Nodes represent threat entities (IOCs, actors, campaigns, techniques).
    Edges model typed relationships with confidence weights. Supports
    graph traversal, PageRank-based prioritization, and component detection.
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, GraphNode] = {}
        self._adj: Dict[str, List[GraphEdge]] = defaultdict(list)
        self._radj: Dict[str, List[GraphEdge]] = defaultdict(list)
        self._edge_keys: Set[Tuple[str, str, str]] = set()

    # ------------------------------------------------------------------ nodes

    def add_node(self, node: GraphNode) -> None:
        self._nodes[node.node_id] = node

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    def iter_nodes(self, node_type: Optional[NodeType] = None) -> Iterator[GraphNode]:
        for node in self._nodes.values():
            if node_type is None or node.node_type == node_type:
                yield node

    # ------------------------------------------------------------------ edges

    def add_edge(self, edge: GraphEdge) -> bool:
        """Add directed edge; returns False if it already exists."""
        if edge.key in self._edge_keys:
            return False
        if edge.source_id not in self._nodes or edge.target_id not in self._nodes:
            raise ValueError(
                f"Both nodes must exist before adding edge {edge.key!r}"
            )
        self._adj[edge.source_id].append(edge)
        self._radj[edge.target_id].append(edge)
        self._edge_keys.add(edge.key)
        return True

    def outgoing_edges(self, node_id: str) -> List[GraphEdge]:
        return list(self._adj.get(node_id, []))

    def incoming_edges(self, node_id: str) -> List[GraphEdge]:
        return list(self._radj.get(node_id, []))

    def neighbors(self, node_id: str) -> List[str]:
        return [e.target_id for e in self._adj.get(node_id, [])]

    def predecessors(self, node_id: str) -> List[str]:
        return [e.source_id for e in self._radj.get(node_id, [])]

    # ------------------------------------------------------- domain importers

    def add_ioc(self, ioc: IOC) -> GraphNode:
        """Import an IOC as a graph node, wiring MITRE technique edges."""
        node_id = f"ioc:{ioc.fingerprint}"
        node = GraphNode(
            node_id=node_id,
            node_type=NodeType.IOC,
            label=f"{ioc.ioc_type.value}:{ioc.value}",
            attributes={
                "ioc_type": ioc.ioc_type.value,
                "value": ioc.value,
                "severity": ioc.severity.value,
                "confidence": ioc.confidence,
                "source": ioc.source,
                "tags": list(ioc.tags),
                "mitre_techniques": ioc.mitre_techniques,
            },
            weight=ioc.risk_score / 100.0,
        )
        self.add_node(node)

        for tech in ioc.mitre_techniques:
            tech_id = f"technique:{tech}"
            if tech_id not in self._nodes:
                self.add_node(GraphNode(
                    node_id=tech_id,
                    node_type=NodeType.TECHNIQUE,
                    label=tech,
                ))
            self.add_edge(GraphEdge(
                source_id=node_id,
                target_id=tech_id,
                relation=RelationType.INDICATES,
                confidence=ioc.confidence / 100.0,
            ))

        src_id = f"source:{ioc.source}"
        if src_id not in self._nodes:
            self.add_node(GraphNode(
                node_id=src_id,
                node_type=NodeType.TOOL,
                label=ioc.source,
                attributes={"type": "feed_source"},
            ))
        self.add_edge(GraphEdge(
            source_id=src_id,
            target_id=node_id,
            relation=RelationType.USES,
            confidence=1.0,
        ))
        return node

    def add_threat_actor(self, actor: ThreatActor) -> GraphNode:
        """Import a ThreatActor as a graph node."""
        node_id = f"actor:{actor.id}"
        node = GraphNode(
            node_id=node_id,
            node_type=NodeType.THREAT_ACTOR,
            label=actor.name,
            attributes={
                "aliases": actor.aliases,
                "motivation": actor.motivation,
                "sophistication": actor.sophistication,
                "mitre_groups": actor.mitre_groups,
            },
        )
        self.add_node(node)

        for fp in actor.associated_iocs:
            ioc_node_id = f"ioc:{fp}"
            if ioc_node_id in self._nodes:
                self.add_edge(GraphEdge(
                    source_id=node_id,
                    target_id=ioc_node_id,
                    relation=RelationType.USES,
                    confidence=0.8,
                ))

        for group in actor.mitre_groups:
            group_id = f"technique:group:{group}"
            if group_id not in self._nodes:
                self.add_node(GraphNode(
                    node_id=group_id,
                    node_type=NodeType.TECHNIQUE,
                    label=group,
                ))
            self.add_edge(GraphEdge(
                source_id=node_id,
                target_id=group_id,
                relation=RelationType.PART_OF,
                confidence=1.0,
            ))
        return node

    # ------------------------------------------------------------ traversal

    def bfs(self, start_id: str, max_depth: int = 3) -> Dict[str, int]:
        """BFS from start node. Returns {node_id: depth}."""
        if start_id not in self._nodes:
            return {}
        visited: Dict[str, int] = {start_id: 0}
        queue: deque[Tuple[str, int]] = deque([(start_id, 0)])
        while queue:
            node_id, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for neighbor in self.neighbors(node_id):
                if neighbor not in visited:
                    visited[neighbor] = depth + 1
                    queue.append((neighbor, depth + 1))
        return visited

    def shortest_path(self, source_id: str, target_id: str) -> Optional[PathResult]:
        """BFS shortest path. Returns None if unreachable."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return None
        if source_id == target_id:
            return PathResult(
                source=source_id, target=target_id,
                path=[source_id], edges=[], total_confidence=1.0,
            )

        visited: Set[str] = {source_id}
        parent: Dict[str, Tuple[str, GraphEdge]] = {}
        queue: deque[str] = deque([source_id])
        found = False

        while queue and not found:
            current = queue.popleft()
            for edge in self._adj.get(current, []):
                neighbor = edge.target_id
                if neighbor not in visited:
                    visited.add(neighbor)
                    parent[neighbor] = (current, edge)
                    if neighbor == target_id:
                        found = True
                        break
                    queue.append(neighbor)

        if not found:
            return None

        path: List[str] = []
        edges: List[GraphEdge] = []
        current = target_id
        while current != source_id:
            path.append(current)
            prev, edge = parent[current]
            edges.append(edge)
            current = prev
        path.append(source_id)
        path.reverse()
        edges.reverse()

        total_confidence = 1.0
        for edge in edges:
            total_confidence *= edge.confidence

        return PathResult(
            source=source_id, target=target_id,
            path=path, edges=edges,
            total_confidence=total_confidence,
        )

    # ----------------------------------------------------- centrality / rank

    def degree_centrality(self) -> Dict[str, float]:
        """Normalized degree centrality (in + out) for all nodes."""
        n = len(self._nodes)
        if n <= 1:
            return {nid: 0.0 for nid in self._nodes}
        result: Dict[str, float] = {}
        for node_id in self._nodes:
            in_deg = len(self._radj.get(node_id, []))
            out_deg = len(self._adj.get(node_id, []))
            result[node_id] = (in_deg + out_deg) / (2 * (n - 1))
        return result

    def pagerank(
        self,
        damping: float = 0.85,
        iterations: int = 50,
        tol: float = 1e-6,
    ) -> Dict[str, float]:
        """
        Power-iteration PageRank with confidence-weighted edges.
        Teleportation probability = 1 - damping.
        """
        n = len(self._nodes)
        if n == 0:
            return {}

        node_ids = list(self._nodes.keys())
        idx: Dict[str, int] = {nid: i for i, nid in enumerate(node_ids)}
        rank = [1.0 / n] * n

        for _ in range(iterations):
            new_rank = [(1.0 - damping) / n] * n
            for src_id, edges in self._adj.items():
                if not edges:
                    continue
                src_idx = idx[src_id]
                total_conf = sum(e.confidence for e in edges)
                if total_conf == 0.0:
                    continue
                for edge in edges:
                    tgt_idx = idx[edge.target_id]
                    new_rank[tgt_idx] += (
                        damping * rank[src_idx] * (edge.confidence / total_conf)
                    )

            delta = sum(abs(new_rank[i] - rank[i]) for i in range(n))
            rank = new_rank
            if delta < tol:
                break

        return {node_ids[i]: rank[i] for i in range(n)}

    def top_threats(self, top_n: int = 10) -> List[PageRankResult]:
        """Return top-N threat-relevant nodes by PageRank score."""
        scores = self.pagerank()
        threat_types = {NodeType.IOC, NodeType.THREAT_ACTOR, NodeType.CAMPAIGN}
        results = [
            PageRankResult(
                node_id=nid,
                score=score,
                node_type=self._nodes[nid].node_type,
                label=self._nodes[nid].label,
            )
            for nid, score in scores.items()
            if self._nodes[nid].node_type in threat_types
        ]
        results.sort(key=lambda r: r.score, reverse=True)
        return results[:top_n]

    # ------------------------------------------------- component detection

    def connected_components(self) -> List[Set[str]]:
        """Weakly connected components (edges treated as undirected)."""
        visited: Set[str] = set()
        components: List[Set[str]] = []

        for node_id in self._nodes:
            if node_id in visited:
                continue
            component: Set[str] = set()
            stack = [node_id]
            while stack:
                current = stack.pop()
                if current in component:
                    continue
                component.add(current)
                stack.extend(n for n in self.neighbors(current) if n not in component)
                stack.extend(p for p in self.predecessors(current) if p not in component)
            visited.update(component)
            components.append(component)

        components.sort(key=len, reverse=True)
        return components

    # -------------------------------------------------------- domain queries

    def find_related_iocs(self, ioc: IOC, max_depth: int = 2) -> List[GraphNode]:
        """
        Find IOC nodes related to the given IOC within max_depth hops,
        following edges in both directions (bidirectional BFS).
        This surfaces IOCs that share intermediate nodes such as MITRE techniques.
        """
        node_id = f"ioc:{ioc.fingerprint}"
        if node_id not in self._nodes:
            return []

        visited: Dict[str, int] = {node_id: 0}
        queue: deque[Tuple[str, int]] = deque([(node_id, 0)])
        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for neighbor in self.neighbors(current) + self.predecessors(current):
                if neighbor not in visited:
                    visited[neighbor] = depth + 1
                    queue.append((neighbor, depth + 1))

        return [
            self._nodes[nid]
            for nid in visited
            if nid != node_id and self._nodes[nid].node_type == NodeType.IOC
        ]

    def campaign_attribution(self, ioc: IOC) -> List[GraphNode]:
        """Walk backwards from IOC to find attributed campaigns and actors."""
        node_id = f"ioc:{ioc.fingerprint}"
        if node_id not in self._nodes:
            return []

        results: List[GraphNode] = []
        visited: Set[str] = {node_id}
        queue: deque[str] = deque([node_id])
        while queue:
            current = queue.popleft()
            for pred in self.predecessors(current):
                if pred not in visited:
                    visited.add(pred)
                    node = self._nodes[pred]
                    if node.node_type in (NodeType.THREAT_ACTOR, NodeType.CAMPAIGN):
                        results.append(node)
                    queue.append(pred)
        return results

    # --------------------------------------------------------- stats / I/O

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return len(self._edge_keys)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [
                {
                    "id": n.node_id,
                    "type": n.node_type.value,
                    "label": n.label,
                    "weight": n.weight,
                    "attributes": n.attributes,
                }
                for n in self._nodes.values()
            ],
            "edges": [
                {
                    "source": e.source_id,
                    "target": e.target_id,
                    "relation": e.relation.value,
                    "confidence": e.confidence,
                    "attributes": e.attributes,
                }
                for edges in self._adj.values()
                for e in edges
            ],
            "stats": {
                "node_count": self.node_count(),
                "edge_count": self.edge_count(),
                "component_count": len(self.connected_components()),
            },
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatGraph":
        graph = cls()
        for n in data.get("nodes", []):
            graph.add_node(GraphNode(
                node_id=n["id"],
                node_type=NodeType(n["type"]),
                label=n["label"],
                weight=n.get("weight", 1.0),
                attributes=n.get("attributes", {}),
            ))
        for e in data.get("edges", []):
            graph.add_edge(GraphEdge(
                source_id=e["source"],
                target_id=e["target"],
                relation=RelationType(e["relation"]),
                confidence=e.get("confidence", 1.0),
                attributes=e.get("attributes", {}),
            ))
        return graph

    @classmethod
    def from_json(cls, json_str: str) -> "ThreatGraph":
        return cls.from_dict(json.loads(json_str))


class GraphBuilder:
    """Fluent builder for constructing threat graphs from Overwatch domain objects."""

    def __init__(self) -> None:
        self._graph = ThreatGraph()

    def add_iocs(self, iocs: List[IOC]) -> "GraphBuilder":
        for ioc in iocs:
            self._graph.add_ioc(ioc)
        return self

    def add_actors(self, actors: List[ThreatActor]) -> "GraphBuilder":
        for actor in actors:
            self._graph.add_threat_actor(actor)
        return self

    def link_iocs_by_campaign(
        self, campaign_name: str, ioc_fingerprints: List[str]
    ) -> "GraphBuilder":
        campaign_id = f"campaign:{campaign_name.lower().replace(' ', '_')}"
        if campaign_id not in self._graph._nodes:
            self._graph.add_node(GraphNode(
                node_id=campaign_id,
                node_type=NodeType.CAMPAIGN,
                label=campaign_name,
            ))
        for fp in ioc_fingerprints:
            ioc_node_id = f"ioc:{fp}"
            if ioc_node_id in self._graph._nodes:
                self._graph.add_edge(GraphEdge(
                    source_id=campaign_id,
                    target_id=ioc_node_id,
                    relation=RelationType.USES,
                    confidence=0.9,
                ))
        return self

    def link_actor_to_campaign(
        self,
        actor_name: str,
        campaign_name: str,
        confidence: float = 0.8,
    ) -> "GraphBuilder":
        actor_nodes = [
            n for n in self._graph._nodes.values()
            if n.node_type == NodeType.THREAT_ACTOR and n.label == actor_name
        ]
        campaign_id = f"campaign:{campaign_name.lower().replace(' ', '_')}"
        if not actor_nodes or campaign_id not in self._graph._nodes:
            return self
        self._graph.add_edge(GraphEdge(
            source_id=actor_nodes[0].node_id,
            target_id=campaign_id,
            relation=RelationType.ATTRIBUTED_TO,
            confidence=confidence,
        ))
        return self

    def build(self) -> ThreatGraph:
        return self._graph
