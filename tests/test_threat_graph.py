"""
Tests for the threat intelligence knowledge graph.
"""

from __future__ import annotations

import json

import pytest

from overwatch.models import IOC, IOCType, Severity, TLPLevel, ThreatActor
from overwatch.threat_graph import (
    GraphBuilder,
    GraphEdge,
    GraphNode,
    NodeType,
    PageRankResult,
    RelationType,
    ThreatGraph,
)


# ------------------------------------------------------------------ fixtures


def make_ioc(
    value: str,
    ioc_type: IOCType = IOCType.IPV4,
    severity: Severity = Severity.HIGH,
    confidence: int = 80,
    source: str = "test-feed",
    techniques: list | None = None,
) -> IOC:
    return IOC(
        ioc_type=ioc_type,
        value=value,
        source=source,
        severity=severity,
        confidence=confidence,
        mitre_techniques=techniques or [],
    )


def make_actor(name: str, ioc_fps: list | None = None, groups: list | None = None) -> ThreatActor:
    return ThreatActor(
        name=name,
        associated_iocs=ioc_fps or [],
        mitre_groups=groups or [],
        motivation="espionage",
        sophistication="advanced",
    )


# ----------------------------------------------------------------- basic ops


class TestThreatGraphBasics:
    def test_add_node_and_retrieve(self):
        g = ThreatGraph()
        node = GraphNode(node_id="ioc:abc", node_type=NodeType.IOC, label="1.2.3.4")
        g.add_node(node)
        assert g.get_node("ioc:abc") is node
        assert g.node_count() == 1

    def test_add_edge_success(self):
        g = ThreatGraph()
        g.add_node(GraphNode("a", NodeType.IOC, "A"))
        g.add_node(GraphNode("b", NodeType.TECHNIQUE, "B"))
        edge = GraphEdge("a", "b", RelationType.INDICATES)
        assert g.add_edge(edge) is True
        assert g.edge_count() == 1

    def test_add_duplicate_edge_returns_false(self):
        g = ThreatGraph()
        g.add_node(GraphNode("a", NodeType.IOC, "A"))
        g.add_node(GraphNode("b", NodeType.TECHNIQUE, "B"))
        e = GraphEdge("a", "b", RelationType.INDICATES)
        g.add_edge(e)
        assert g.add_edge(e) is False
        assert g.edge_count() == 1

    def test_add_edge_missing_node_raises(self):
        g = ThreatGraph()
        g.add_node(GraphNode("a", NodeType.IOC, "A"))
        with pytest.raises(ValueError):
            g.add_edge(GraphEdge("a", "missing", RelationType.INDICATES))

    def test_neighbors_and_predecessors(self):
        g = ThreatGraph()
        g.add_node(GraphNode("a", NodeType.IOC, "A"))
        g.add_node(GraphNode("b", NodeType.IOC, "B"))
        g.add_edge(GraphEdge("a", "b", RelationType.RELATED_TO))
        assert g.neighbors("a") == ["b"]
        assert g.predecessors("b") == ["a"]
        assert g.neighbors("b") == []


# --------------------------------------------------------- domain importers


class TestAddIoc:
    def test_add_ioc_creates_node(self):
        ioc = make_ioc("192.168.1.1")
        g = ThreatGraph()
        node = g.add_ioc(ioc)
        assert node.node_type == NodeType.IOC
        assert g.get_node(node.node_id) is node

    def test_add_ioc_creates_technique_nodes(self):
        ioc = make_ioc("evil.com", IOCType.DOMAIN, techniques=["T1071", "T1059"])
        g = ThreatGraph()
        g.add_ioc(ioc)
        assert g.get_node("technique:T1071") is not None
        assert g.get_node("technique:T1059") is not None

    def test_add_ioc_creates_technique_edges(self):
        ioc = make_ioc("evil.com", IOCType.DOMAIN, techniques=["T1071"])
        g = ThreatGraph()
        node = g.add_ioc(ioc)
        outgoing = g.outgoing_edges(node.node_id)
        relations = {e.relation for e in outgoing}
        assert RelationType.INDICATES in relations

    def test_add_ioc_creates_source_node(self):
        ioc = make_ioc("1.1.1.1", source="abuse.ch")
        g = ThreatGraph()
        g.add_ioc(ioc)
        assert g.get_node("source:abuse.ch") is not None

    def test_add_threat_actor_links_iocs(self):
        ioc = make_ioc("10.0.0.1")
        g = ThreatGraph()
        ioc_node = g.add_ioc(ioc)
        actor = make_actor("APT29", ioc_fps=[ioc.fingerprint])
        actor_node = g.add_threat_actor(actor)
        outgoing = g.outgoing_edges(actor_node.node_id)
        targets = {e.target_id for e in outgoing}
        assert ioc_node.node_id in targets

    def test_add_threat_actor_creates_group_nodes(self):
        actor = make_actor("FancyBear", groups=["G0007"])
        g = ThreatGraph()
        g.add_threat_actor(actor)
        assert g.get_node("technique:group:G0007") is not None


# --------------------------------------------------------------- traversal


class TestBFS:
    def test_bfs_single_node(self):
        g = ThreatGraph()
        g.add_node(GraphNode("a", NodeType.IOC, "A"))
        result = g.bfs("a")
        assert result == {"a": 0}

    def test_bfs_depth_limit(self):
        g = ThreatGraph()
        for name in ["a", "b", "c", "d"]:
            g.add_node(GraphNode(name, NodeType.IOC, name.upper()))
        g.add_edge(GraphEdge("a", "b", RelationType.RELATED_TO))
        g.add_edge(GraphEdge("b", "c", RelationType.RELATED_TO))
        g.add_edge(GraphEdge("c", "d", RelationType.RELATED_TO))

        result = g.bfs("a", max_depth=2)
        assert "b" in result and result["b"] == 1
        assert "c" in result and result["c"] == 2
        assert "d" not in result

    def test_bfs_missing_start_returns_empty(self):
        g = ThreatGraph()
        assert g.bfs("nonexistent") == {}


class TestShortestPath:
    def test_direct_path(self):
        g = ThreatGraph()
        g.add_node(GraphNode("a", NodeType.IOC, "A"))
        g.add_node(GraphNode("b", NodeType.TECHNIQUE, "B"))
        g.add_edge(GraphEdge("a", "b", RelationType.INDICATES, confidence=0.9))
        result = g.shortest_path("a", "b")
        assert result is not None
        assert result.path == ["a", "b"]
        assert abs(result.total_confidence - 0.9) < 1e-9

    def test_multi_hop_path(self):
        g = ThreatGraph()
        for n in ["a", "b", "c"]:
            g.add_node(GraphNode(n, NodeType.IOC, n.upper()))
        g.add_edge(GraphEdge("a", "b", RelationType.RELATED_TO, confidence=0.8))
        g.add_edge(GraphEdge("b", "c", RelationType.RELATED_TO, confidence=0.5))
        result = g.shortest_path("a", "c")
        assert result is not None
        assert result.path == ["a", "b", "c"]
        assert abs(result.total_confidence - 0.4) < 1e-9

    def test_no_path_returns_none(self):
        g = ThreatGraph()
        g.add_node(GraphNode("a", NodeType.IOC, "A"))
        g.add_node(GraphNode("b", NodeType.IOC, "B"))
        assert g.shortest_path("a", "b") is None

    def test_same_node_path(self):
        g = ThreatGraph()
        g.add_node(GraphNode("a", NodeType.IOC, "A"))
        result = g.shortest_path("a", "a")
        assert result is not None
        assert result.path == ["a"]
        assert result.total_confidence == 1.0


# --------------------------------------------------------- centrality


class TestPageRank:
    def test_empty_graph(self):
        assert ThreatGraph().pagerank() == {}

    def test_single_node(self):
        g = ThreatGraph()
        g.add_node(GraphNode("a", NodeType.IOC, "A"))
        scores = g.pagerank()
        assert "a" in scores
        assert scores["a"] > 0.0

    def test_hub_node_scores_higher(self):
        """A node that many others point to should score higher."""
        g = ThreatGraph()
        hub = GraphNode("hub", NodeType.TECHNIQUE, "Hub")
        g.add_node(hub)
        for i in range(5):
            leaf_id = f"ioc{i}"
            g.add_node(GraphNode(leaf_id, NodeType.IOC, f"IOC{i}"))
            g.add_edge(GraphEdge(leaf_id, "hub", RelationType.INDICATES))

        scores = g.pagerank()
        assert scores["hub"] > scores["ioc0"]

    def test_top_threats_returns_threat_nodes_only(self):
        g = ThreatGraph()
        g.add_node(GraphNode("ioc:x", NodeType.IOC, "1.2.3.4"))
        g.add_node(GraphNode("actor:y", NodeType.THREAT_ACTOR, "APT1"))
        g.add_node(GraphNode("technique:T1", NodeType.TECHNIQUE, "T1"))
        g.add_node(GraphNode("source:s", NodeType.TOOL, "feed"))

        results = g.top_threats()
        for r in results:
            assert r.node_type in {NodeType.IOC, NodeType.THREAT_ACTOR, NodeType.CAMPAIGN}


class TestDegreeCentrality:
    def test_isolated_node_is_zero(self):
        g = ThreatGraph()
        g.add_node(GraphNode("a", NodeType.IOC, "A"))
        g.add_node(GraphNode("b", NodeType.IOC, "B"))
        dc = g.degree_centrality()
        assert dc["a"] == 0.0

    def test_connected_node_higher_than_leaf(self):
        g = ThreatGraph()
        for n in ["a", "b", "c"]:
            g.add_node(GraphNode(n, NodeType.IOC, n))
        g.add_edge(GraphEdge("a", "b", RelationType.RELATED_TO))
        g.add_edge(GraphEdge("c", "b", RelationType.RELATED_TO))
        dc = g.degree_centrality()
        assert dc["b"] > dc["a"]


# --------------------------------------------------- connected components


class TestConnectedComponents:
    def test_two_separate_components(self):
        g = ThreatGraph()
        for n in ["a", "b", "c", "d"]:
            g.add_node(GraphNode(n, NodeType.IOC, n))
        g.add_edge(GraphEdge("a", "b", RelationType.RELATED_TO))
        g.add_edge(GraphEdge("c", "d", RelationType.RELATED_TO))
        components = g.connected_components()
        assert len(components) == 2
        sizes = sorted(len(c) for c in components)
        assert sizes == [2, 2]

    def test_all_connected(self):
        g = ThreatGraph()
        for n in ["a", "b", "c"]:
            g.add_node(GraphNode(n, NodeType.IOC, n))
        g.add_edge(GraphEdge("a", "b", RelationType.RELATED_TO))
        g.add_edge(GraphEdge("b", "c", RelationType.RELATED_TO))
        assert len(g.connected_components()) == 1


# ------------------------------------------------------------ domain queries


class TestDomainQueries:
    def test_find_related_iocs(self):
        ioc_a = make_ioc("10.0.0.1", techniques=["T1071"])
        ioc_b = make_ioc("10.0.0.2", techniques=["T1071"])
        g = ThreatGraph()
        g.add_ioc(ioc_a)
        g.add_ioc(ioc_b)
        related = g.find_related_iocs(ioc_a, max_depth=2)
        related_ids = {n.node_id for n in related}
        assert f"ioc:{ioc_b.fingerprint}" in related_ids

    def test_campaign_attribution(self):
        ioc = make_ioc("badactor.com", IOCType.DOMAIN)
        actor = make_actor("LAZARUS", ioc_fps=[ioc.fingerprint])
        g = ThreatGraph()
        g.add_ioc(ioc)
        g.add_threat_actor(actor)
        attributed = g.campaign_attribution(ioc)
        labels = {n.label for n in attributed}
        assert "LAZARUS" in labels

    def test_campaign_attribution_missing_ioc_returns_empty(self):
        ioc = make_ioc("1.2.3.4")
        g = ThreatGraph()
        assert g.campaign_attribution(ioc) == []


# --------------------------------------------------------------- serialization


class TestSerialization:
    def test_round_trip_json(self):
        g = ThreatGraph()
        g.add_node(GraphNode("a", NodeType.IOC, "1.1.1.1", weight=0.7))
        g.add_node(GraphNode("b", NodeType.TECHNIQUE, "T1071"))
        g.add_edge(GraphEdge("a", "b", RelationType.INDICATES, confidence=0.9))

        json_str = g.to_json()
        g2 = ThreatGraph.from_json(json_str)
        assert g2.node_count() == g.node_count()
        assert g2.edge_count() == g.edge_count()

    def test_to_dict_contains_stats(self):
        g = ThreatGraph()
        d = g.to_dict()
        assert "stats" in d
        assert d["stats"]["node_count"] == 0


# ------------------------------------------------------------ GraphBuilder


class TestGraphBuilder:
    def test_builder_add_iocs_and_actors(self):
        ioc = make_ioc("evil.net", IOCType.DOMAIN)
        actor = make_actor("APT1", ioc_fps=[ioc.fingerprint])
        graph = (
            GraphBuilder()
            .add_iocs([ioc])
            .add_actors([actor])
            .build()
        )
        assert graph.get_node(f"ioc:{ioc.fingerprint}") is not None
        actor_nodes = list(graph.iter_nodes(NodeType.THREAT_ACTOR))
        assert len(actor_nodes) == 1
        assert actor_nodes[0].label == "APT1"

    def test_builder_link_by_campaign(self):
        ioc1 = make_ioc("1.1.1.1")
        ioc2 = make_ioc("2.2.2.2")
        graph = (
            GraphBuilder()
            .add_iocs([ioc1, ioc2])
            .link_iocs_by_campaign("OpFoo", [ioc1.fingerprint, ioc2.fingerprint])
            .build()
        )
        campaign_nodes = list(graph.iter_nodes(NodeType.CAMPAIGN))
        assert len(campaign_nodes) == 1
        assert campaign_nodes[0].label == "OpFoo"

    def test_builder_link_actor_to_campaign(self):
        ioc = make_ioc("3.3.3.3")
        actor = make_actor("FIN7")
        graph = (
            GraphBuilder()
            .add_iocs([ioc])
            .add_actors([actor])
            .link_iocs_by_campaign("OpBar", [ioc.fingerprint])
            .link_actor_to_campaign("FIN7", "OpBar", confidence=0.75)
            .build()
        )
        actor_nodes = list(graph.iter_nodes(NodeType.THREAT_ACTOR))
        assert actor_nodes
        actor_node = actor_nodes[0]
        campaign_id = "campaign:opbar"
        result = graph.shortest_path(actor_node.node_id, campaign_id)
        assert result is not None
