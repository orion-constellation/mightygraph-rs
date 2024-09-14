
// Standard library imports
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;

// External crate imports
use serde::{Deserialize, Serialize};
use serde_json::json;

use polars::prelude::*;
use petgraph::graph::{Graph, NodeIndex};
use petgraph::algo::{connected_components, dijkstra};
use csv::Reader;
use chrono::NaiveDate;

// Struct Definitions
#[derive(Debug, Deserialize, Serialize)]
pub struct Mapping {
    pub mapping_framework: String,
    pub mapping_framework_version: String,
    pub capability_group: String,
    pub capability_id: String,
    pub capability_description: String,
    pub mapping_type: String,
    pub attack_object_id: String,
    pub attack_object_name: String,
    pub attack_version: String,
    pub technology_domain: String,
    pub references: String,
    pub comments: String,
    pub organization: String,
    pub creation_date: String,
    pub last_update: String,
}

#[derive(Debug, Serialize)]
pub struct NodeData {
    pub id: String,
    pub node_type: NodeType,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum NodeType {
    Veris,
    Mitre,
}

#[derive(Debug, Serialize)]
pub struct EdgeData {
    pub mapping_type: String,
    pub strength: f32,
}

pub type MappingGraph = Graph<NodeData, EdgeData>;

// Function Definitions
pub fn add_node_if_not_exists(
    graph: &mut MappingGraph,
    node_indices: &mut HashMap<String, NodeIndex>,
    node_id: &str,
    node_type: NodeType,
) -> NodeIndex {
    if let Some(&index) = node_indices.get(node_id) {
        index
    } else {
        let node_data = NodeData {
            id: node_id.to_string(),
            node_type,
            metadata: HashMap::new(),
        };
        let index = graph.add_node(node_data);
        node_indices.insert(node_id.to_string(), index);
        index
    }
}

pub fn calculate_strength(mapping: &Mapping) -> f32 {
    // Assuming some logic for calculating strength, modify as per the actual logic
    1.0 // Placeholder value
}

pub fn export_to_json<T: Serialize>(name: &str, data: &T) -> Result<(), Box<dyn std::error::Error>> {
    let dir = Path::new("./analysed/data");
    fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.json", name));
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, data)?;
    Ok(())
}

// Analysis Functions
pub fn perform_basic_stats(graph: &MappingGraph, mappings: &[Mapping]) -> serde_json::Value {
    json!({
        "total_mappings": mappings.len(),
        "total_nodes": graph.node_count(),
        "total_edges": graph.edge_count(),
    })
}

pub fn perform_node_degree_analysis(graph: &MappingGraph) -> serde_json::Value {
    let mut node_degrees: Vec<_> = graph.node_indices()
        .map(|n| (graph[n].id.clone(), graph.neighbors(n).count()))
        .collect();
    node_degrees.sort_by_key(|&(_, degree)| std::cmp::Reverse(degree));
    json!(node_degrees.into_iter().collect::<HashMap<_, _>>())
}