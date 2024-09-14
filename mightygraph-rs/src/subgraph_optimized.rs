use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::algo::{kosaraju_scc, dijkstra};
use petgraph::visit::EdgeRef;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MitreObject {
    id: String,
    name: String,
    object_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Relationship {
    source_ref: String,
    target_ref: String,
    relationship_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MitreData {
    objects: Vec<MitreObject>,
    relationships: Vec<Relationship>,
}

fn load_mitre_data(file_path: &str) -> MitreData {
    let file = File::open(file_path).expect("Unable to open file");
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).expect("Unable to parse JSON")
}

fn build_graph(data: &MitreData) -> (DiGraph<MitreObject, String>, HashMap<String, NodeIndex>) {
    let mut graph = DiGraph::new();
    let mut node_map = HashMap::new();

    for obj in &data.objects {
        let node_index = graph.add_node(obj.clone());
        node_map.insert(obj.id.clone(), node_index);
    }

    for rel in &data.relationships {
        if let (Some(&source), Some(&target)) = (node_map.get(&rel.source_ref), node_map.get(&rel.target_ref)) {
            graph.add_edge(source, target, rel.relationship_type.clone());
        }
    }

    (graph, node_map)
}

fn calculate_novelty_score(graph: &DiGraph<MitreObject, String>, node: NodeIndex) -> f64 {
    let mut score = 0.0;

    // Factor 1: Uniqueness of connections
    let edges = graph.edges(node).collect::<Vec<_>>();
    let unique_connections = edges.iter().map(|e| e.weight()).collect::<HashSet<_>>().len();
    score += (unique_connections as f64) / (edges.len() as f64);

    // Factor 2: Betweenness centrality approximation
    let scc = kosaraju_scc(&graph);
    let component_size = scc.iter().find(|comp| comp.contains(&node)).map_or(0, |comp| comp.len());
    score += 1.0 - (component_size as f64) / (graph.node_count() as f64);

    // Factor 3: Path diversity
    let distances = dijkstra(&graph, node, None, |_| 1);
    let avg_distance = distances.values().sum::<i32>() as f64 / distances.len() as f64;
    score += 1.0 / (1.0 + avg_distance);

    score / 3.0  // Normalize the score
}

fn subsample_novel_techniques(graph: &DiGraph<MitreObject, String>, threshold: f64, sample_size: usize) -> Vec<NodeIndex> {
    let mut novelty_scores: Vec<(NodeIndex, f64)> = graph
        .node_indices()
        .map(|node| (node, calculate_novelty_score(graph, node)))
        .collect();

    novelty_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    let potential_novel_techniques: Vec<NodeIndex> = novelty_scores
        .into_iter()
        .filter(|(_, score)| *score > threshold)
        .map(|(node, _)| node)
        .collect();

    potential_novel_techniques
        .choose_multiple(&mut rand::thread_rng(), sample_size)
        .cloned()
        .collect()
}

fn extract_subgraph(graph: &DiGraph<MitreObject, String>, nodes: &[NodeIndex], depth: usize) -> DiGraph<MitreObject, String> {
    let mut subgraph = DiGraph::new();
    let mut node_map = HashMap::new();

    for &node in nodes {
        let mut queue = vec![(node, 0)];
        let mut visited = HashSet::new();

        while let Some((current, current_depth)) = queue.pop() {
            if current_depth > depth || visited.contains(&current) {
                continue;
            }

            visited.insert(current);
            let subgraph_node = *node_map.entry(current).or_insert_with(|| {
                subgraph.add_node(graph[current].clone())
            });

            for edge in graph.edges(current) {
                let neighbor = edge.target();
                let subgraph_neighbor = *node_map.entry(neighbor).or_insert_with(|| {
                    subgraph.add_node(graph[neighbor].clone())
                });

                subgraph.add_edge(subgraph_node, subgraph_neighbor, edge.weight().clone());

                if current_depth < depth {
                    queue.push((neighbor, current_depth + 1));
                }
            }
        }
    }

    subgraph
}

fn main() {
    let data = load_mitre_data("enterprise-attack.json");
    let (graph, _) = build_graph(&data);

    let novelty_threshold = 0.7;
    let sample_size = 5;
    let subgraph_depth = 2;

    let novel_techniques = subsample_novel_techniques(&graph, novelty_threshold, sample_size);
    let subgraph = extract_subgraph(&graph, &novel_techniques, subgraph_depth);

    println!("Potential novel techniques:");
    for node in subgraph.node_indices() {
        println!("- {}: {}", subgraph[node].name, subgraph[node].id);
    }

    println!("\nSubgraph statistics:");
    println!("Nodes: {}", subgraph.node_count());
    println!("Edges: {}", subgraph.edge_count());
}