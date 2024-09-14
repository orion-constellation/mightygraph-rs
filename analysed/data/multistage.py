"""
#Py Based on GQAlchemy

""" 

import json
import rustworkx as rx
from typing import Dict, List, Tuple
import numpy as np
from community import community_louvain
from gqlalchemy import Memgraph

def load_mitre_data(file_path: str) -> Dict:
    with open(file_path, 'r') as f:
        return json.load(f)

def create_knowledge_graph(data: Dict) -> rx.PyGraph:
    G = rx.PyGraph()
    node_map = {}  # Map MITRE IDs to graph node indices

    # Add nodes
    for obj in data['objects']:
        if obj['type'] in ['attack-pattern', 'course-of-action', 'intrusion-set', 'malware', 'tool']:
            node_id = G.add_node((obj['type'], obj['id'], obj['name']))
            node_map[obj['id']] = node_id

    # Add edges
    for obj in data['objects']:
        if 'relationship_type' in obj:
            source = node_map.get(obj['source_ref'])
            target = node_map.get(obj['target_ref'])
            if source is not None and target is not None:
                G.add_edge(source, target, obj['relationship_type'])

    return G, node_map

def analyze_graph(G: rx.PyGraph) -> Tuple[List[int], Dict, List[float], List[float]]:
    degrees = G.degree()
    adj_matrix = rx.adjacency_matrix(G)
    partition = community_louvain.best_partition(adj_matrix)
    clustering_coeffs = rx.clustering_coefficients(G)
    betweenness = rx.betweenness_centrality(G)
    return degrees, partition, clustering_coeffs, betweenness

def calculate_multi_stage_attack_commonality(G: rx.PyGraph) -> List[float]:
    paths = rx.all_pairs_shortest_path_lengths(G)
    max_path_length = max(max(lengths.values()) for lengths in paths.values())
    multi_stage_counts = [0] * G.num_nodes()
    
    for source in paths:
        for target, length in paths[source].items():
            if length > 1:
                multi_stage_counts[source] += 1
                multi_stage_counts[target] += 1

    max_count = max(multi_stage_counts)
    return [count / max_count for count in multi_stage_counts]

def identify_common_impacts(G: rx.PyGraph, betweenness: List[float]) -> List[float]:
    normalized_betweenness = [b / max(betweenness) for b in betweenness]
    degrees = G.degree()
    max_degree = max(degrees)
    normalized_degrees = [d / max_degree for d in degrees]
    
    return [(b + d) / 2 for b, d in zip(normalized_betweenness, normalized_degrees)]

def export_to_memgraph(G: rx.PyGraph, node_map: Dict, multi_stage_commonality: List[float], common_impacts: List[float]):
    memgraph = Memgraph()
    
    # Clear existing data
    memgraph.execute("MATCH (n) DETACH DELETE n")
    
    # Create nodes
    for node_id in range(G.num_nodes()):
        node_type, mitre_id, name = G.get_node_data(node_id)
        commonality = multi_stage_commonality[node_id]
        impact = common_impacts[node_id]
        query = """
        CREATE (n:MitreObject {id: $mitre_id, name: $name, type: $node_type, 
                               multi_stage_commonality: $commonality, common_impact: $impact})
        """
        memgraph.execute(query, {'mitre_id': mitre_id, 'name': name, 'node_type': node_type, 
                                 'commonality': commonality, 'impact': impact})
    
    # Create edges
    for edge in G.edge_list():
        source_type, source_id, _ = G.get_node_data(edge[0])
        target_type, target_id, _ = G.get_node_data(edge[1])
        relationship_type = edge[2]
        query = """
        MATCH (s:MitreObject {id: $source_id}), (t:MitreObject {id: $target_id})
        CREATE (s)-[:RELATES {type: $rel_type}]->(t)
        """
        memgraph.execute(query, {'source_id': source_id, 'target_id': target_id, 'rel_type': relationship_type})

def run_cypher_queries(memgraph: Memgraph):
    queries = [
        ("Most common multi-stage attack patterns:", """
        MATCH (n:MitreObject)
        WHERE n.type = 'attack-pattern'
        RETURN n.name, n.multi_stage_commonality
        ORDER BY n.multi_stage_commonality DESC
        LIMIT 5
        """),
        ("Most impactful nodes:", """
        MATCH (n:MitreObject)
        RETURN n.name, n.type, n.common_impact
        ORDER BY n.common_impact DESC
        LIMIT 5
        """),
        ("Most common relationships:", """
        MATCH (s:MitreObject)-[r:RELATES]->(t:MitreObject)
        RETURN r.type, COUNT(*) as count
        ORDER BY count DESC
        LIMIT 5
        """),
        ("Attack patterns with highest connectivity:", """
        MATCH (n:MitreObject {type: 'attack-pattern'})-[r:RELATES]-()
        RETURN n.name, COUNT(r) as connections
        ORDER BY connections DESC
        LIMIT 5
        """)
    ]
    
    for description, query in queries:
        print(f"\n{description}")
        results = memgraph.execute_and_fetch(query)
        for result in results:
            print(result)

def main():
    data = load_mitre_data('enterprise-attack.json')  # Replace with your file path
    G, node_map = create_knowledge_graph(data)
    degrees, communities, clustering_coeffs, betweenness = analyze_graph(G)
    
    multi_stage_commonality = calculate_multi_stage_attack_commonality(G)
    common_impacts = identify_common_impacts(G, betweenness)
    
    export_to_memgraph(G, node_map, multi_stage_commonality, common_impacts)
    
    memgraph = Memgraph()
    run_cypher_queries(memgraph)

if __name__ == "__main__":
    main()