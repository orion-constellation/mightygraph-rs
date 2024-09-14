pub use super::*;
pub use std::collections::{HashMap, HashSet};
pub use petgraph::graph::{Graph, NodeIndex};
pub use petgraph::algo::{connected_components, dijkstra};
pub use serde_json::Value;

pub type MappingGraph = Graph<NodeData, EdgeData>;

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize)]
pub struct AnalysisResults {
    pub basic_stats: Value,
    pub mapping_type_analysis: Value,
    pub node_degree_analysis: Value,
    pub connected_components_analysis: Value,
    pub shortest_path_analysis: Value,
    pub edge_strength_analysis: Value,
    pub node_type_distribution: Value,
    pub temporal_analysis: Value,
    pub tech_domain_analysis: Value,
}