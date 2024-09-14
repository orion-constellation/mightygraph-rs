



use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;
use chrono::NaiveDate;
use petgraph::graph::{Graph, NodeIndex};
use petgraph::algo::{connected_components, dijkstra};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use serde_json::json;
use polars::prelude::*;

#[derive(Debug, Deserialize, Serialize)]
pub struct Mapping {
    mapping_framework: String,
    mapping_framework_version: String,
    capability_group: String,
    capability_id: String,
    capability_description: String,
    mapping_type: String,
    attack_object_id: String,
    attack_object_name: String,
    attack_version: String,
    technology_domain: String,
    references: String,
    comments: String,
    organization: String,
    creation_date: String,
    last_update: String,
}

#[derive(Debug, Serialize)]
pub struct NodeData {
    id: String,
    node_type: NodeType,
    metadata: HashMap<String, String>,
}

#[derive(Debug, PartialEq, Serialize)]
enum NodeType {
    Veris,
    Mitre,
}

#[derive(Debug, Serialize)]
pub struct EdgeData {
    mapping_type: String,
    strength: f32,
}

type MappingGraph = Graph<NodeData, EdgeData>;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load the CSV data
    let file = File::open("veris_mitre_mapping.csv")?;
    let reader = BufReader::new(file);
    let mut rdr = csv::Reader::from_reader(reader);
    let mappings: Vec<Mapping> = rdr.deserialize().collect::<Result<_, _>>()?;

    // Create the graph
    let mut graph = Graph::<NodeData, EdgeData>::new();
    let mut node_indices = HashMap::new();

    for mapping in &mappings {
        let veris_index = add_node_if_not_exists(&mut graph, &mut node_indices, &mapping.capability_id, NodeType::Veris);
        let mitre_index = add_node_if_not_exists(&mut graph, &mut node_indices, &mapping.attack_object_id, NodeType::Mitre);

        let strength = calculate_strength(&mapping);
        graph.add_edge(veris_index, mitre_index, EdgeData {
            mapping_type: mapping.mapping_type.clone(),
            strength,
        });
    }

    // Perform analyses
    let basic_stats = perform_basic_stats(&graph, &mappings);
    let mapping_type_analysis = perform_mapping_type_analysis(&graph);
    let node_degree_analysis = perform_node_degree_analysis(&graph);
    let connected_components_analysis = perform_connected_components_analysis(&graph);
    let shortest_path_analysis = perform_shortest_path_analysis(&graph, &node_indices);
    let edge_strength_analysis = perform_edge_strength_analysis(&graph);
    let node_type_distribution = perform_node_type_distribution(&graph);
    let temporal_analysis = perform_temporal_analysis(&mappings);
    let tech_domain_analysis = perform_tech_domain_analysis(&mappings);

    // 1. Export each artifact to a JSON file
    export_to_json("basic_stats", &basic_stats)?;
    export_to_json("mapping_type_analysis", &mapping_type_analysis)?;
    export_to_json("node_degree_analysis", &node_degree_analysis)?;
    export_to_json("connected_components_analysis", &connected_components_analysis)?;
    export_to_json("shortest_path_analysis", &shortest_path_analysis)?;
    export_to_json("edge_strength_analysis", &edge_strength_analysis)?;
    export_to_json("node_type_distribution", &node_type_distribution)?;
    export_to_json("temporal_analysis", &temporal_analysis)?;
    export_to_json("tech_domain_analysis", &tech_domain_analysis)?;

    // 2 & 3. Combine all information into Parquet and CSV files
    let mut combined_data = vec![];
    for mapping in &mappings {
        let frequency = node_degree_analysis.get(&mapping.attack_object_id).unwrap_or(&0);
        let strength = calculate_strength(&mapping);
        let impact_score = (*frequency as f32 * strength) / 10.0; // Normalize to 0-10 scale

        combined_data.push(json!({
            "veris_id": mapping.capability_id,
            "mitre_id": mapping.attack_object_id,
            "mapping_type": mapping.mapping_type,
            "strength": strength,
            "frequency": frequency,
            "impact_score": impact_score,
            "technology_domain": mapping.technology_domain,
            "creation_date": mapping.creation_date,
        }));
    }

    // Sort by impact score (highest to lowest)
    combined_data.sort_by(|a, b| b["impact_score"].as_f64().partial_cmp(&a["impact_score"].as_f64()).unwrap());

    // Create DataFrame
    let df = DataFrame::new(vec![
        Series::new("veris_id", combined_data.iter().map(|row| row["veris_id"].as_str().unwrap()).collect::<Vec<_>>()),
        Series::new("mitre_id", combined_data.iter().map(|row| row["mitre_id"].as_str().unwrap()).collect::<Vec<_>>()),
        Series::new("mapping_type", combined_data.iter().map(|row| row["mapping_type"].as_str().unwrap()).collect::<Vec<_>>()),
        Series::new("strength", combined_data.iter().map(|row| row["strength"].as_f64().unwrap()).collect::<Vec<_>>()),
        Series::new("frequency", combined_data.iter().map(|row| row["frequency"].as_u64().unwrap() as i32).collect::<Vec<_>>()),
        Series::new("impact_score", combined_data.iter().map(|row| row["impact_score"].as_f64().unwrap()).collect::<Vec<_>>()),
        Series::new("technology_domain", combined_data.iter().map(|row| row["technology_domain"].as_str().unwrap()).collect::<Vec<_>>()),
        Series::new("creation_date", combined_data.iter().map(|row| row["creation_date"].as_str().unwrap()).collect::<Vec<_>>()),
    ])?;

    // Export to Parquet
    let mut file = File::create("./analysed/data/combined_analysis.parquet")?;
    ParquetWriter::new(&mut file).finish(&df)?;

    // Export to CSV
    let mut file = File::create("./analysed/ds/combined_analysis.csv")?;
    CsvWriter::new(&mut file).finish(&df)?;

    Ok(())
}

pub fn export_to_json<T: Serialize>(name: &str, data: &T) -> Result<(), Box<dyn std::error::Error>> {
    let dir = Path::new("./analysed/data");
    fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.json", name));
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, data)?;
    Ok(())
}



pub fn perform_basic_stats(graph: &MappingGraph, mappings: &[Mapping]) -> serde_json::Value {
    json!({
        "total_mappings": mappings.len(),
        "total_nodes": graph.node_count(),
        "total_edges": graph.edge_count(),
    })
}

pub fn perform_mapping_type_analysis(graph: &MappingGraph) -> serde_json::Value {
    let mapping_type_counts = graph.edge_indices()
        .map(|e| &graph[e].mapping_type)
        .fold(HashMap::new(), |mut acc, mt| {
            *acc.entry(mt).or_insert(0) += 1;
            acc
        });
    json!(mapping_type_counts)
}

pub fn perform_node_degree_analysis(graph: &MappingGraph) -> serde_json::Value {
    let mut node_degrees: Vec<_> = graph.node_indices()
        .map(|n| (graph[n].id.clone(), graph.neighbors(n).count()))
        .collect();
    node_degrees.sort_by_key(|&(_, degree)| std::cmp::Reverse(degree));
    json!(node_degrees.into_iter().collect::<HashMap<_, _>>())
}

pub fn perform_connected_components_analysis(graph: &MappingGraph) -> serde_json::Value {
    json!({
        "number_of_components": connected_components(graph),
    })
}

pub fn perform_shortest_path_analysis(graph: &MappingGraph, node_indices: &HashMap<String, NodeIndex>) -> serde_json::Value {
    if let (Some(&start), Some(&end)) = (node_indices.values().next(), node_indices.values().last()) {
        let path = dijkstra(graph, start, Some(end), |e| 1.0 / e.weight().strength);
        if let Some(distance) = path.get(&end) {
            json!({
                "shortest_path_length": distance,
            })
        } else {
            json!({
                "shortest_path_length": null,
                "error": "No path found between first and last node",
            })
        }
    } else {
        json!({
            "error": "Not enough nodes to calculate shortest path",
        })
    }
}

pub fn perform_edge_strength_analysis(graph: &MappingGraph) -> serde_json::Value {
    let mut edge_strengths: Vec<_> = graph.edge_indices()
        .map(|e| (graph[e].mapping_type.clone(), graph[e].strength))
        .collect();
    edge_strengths.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    json!(edge_strengths)
}

pub fn perform_node_type_distribution(graph: &MappingGraph) -> serde_json::Value {
    let node_type_counts = graph.node_indices()
        .map(|n| &graph[n].node_type)
        .fold(HashMap::new(), |mut acc, nt| {
            *acc.entry(format!("{:?}", nt)).or_insert(0) += 1;
            acc
        });
    json!(node_type_counts)
}

pub fn perform_temporal_analysis(mappings: &[Mapping]) -> serde_json::Value {
    let creation_dates: Vec<NaiveDate> = mappings.iter()
        .map(|m| NaiveDate::parse_from_str(&m.creation_date, "%d/%m/%Y").unwrap())
        .collect();
    let min_date = creation_dates.iter().min().unwrap();
    let max_date = creation_dates.iter().max().unwrap();
    json!({
        "min_date": min_date.to_string(),
        "max_date": max_date.to_string(),
    })
}

pub fn perform_tech_domain_analysis(mappings: &[Mapping]) -> serde_json::Value {
    let tech_domain_counts = mappings.iter()
        .map(|m| &m.technology_domain)
        .fold(HashMap::new(), |mut acc, td| {
            *acc.entry(td).or_insert(0) += 1;
            acc
        });
    json!(tech_domain_counts)
}