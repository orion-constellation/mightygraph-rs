pub mod petgraph_full_0x0;

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::Path;
use chrono::NaiveDate;
use petgraph::graph::{Graph, NodeIndex};
use petgraph::algo::{connected_components, dijkstra};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use serde_json::json;
use polars::prelude::*;
use csv;
crate::petgraph_full_0x0::prelude::*;

// Structures definitions remain the same

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;


/// Main function to load CSV data, create a graph, perform analyses, and export results to JSON, Parquet, and CSV.
/// 
/// # Returns
/// 
/// - `Result<()>`: Indicates the success or failure of the main process.
fn main() -> Result<()> {
    // 1. Load the CSV data
    csv_file="/Users/nullzero/Documents/repos/opencti/veris_mitre_map/veris_mitre_map/data /veris-1.3.7_attack-12.1-enterprise.csv"
    let file = File::open(csv_file)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::Reader::from_reader(reader);
    let mappings: Vec<Mapping> = rdr.deserialize().collect::<Result<_, _>>()?;

    // 2. Create the graph and add nodes/edges
    let (graph, node_indices) = create_graph(&mappings)?;

    // 3. Perform the analyses
    let analyses = perform_analyses(&graph, &mappings, &node_indices)?;

    // 4. Export results to JSON
    export_results(&analyses)?;

    // 5. Combine all information and export to Parquet and CSV
    export_combined_data(&mappings, &analyses.node_degree_analysis)?;

    Ok(())
}

fn create_graph(mappings: &[Mapping]) -> Result<(MappingGraph, HashMap<String, NodeIndex>)> {
    let mut graph = Graph::<NodeData, EdgeData>::new();
    let mut node_indices = HashMap::new();

    for mapping in mappings {
        let veris_index = add_node_if_not_exists(&mut graph, &mut node_indices, &mapping.capability_id, NodeType::Veris);
        let mitre_index = add_node_if_not_exists(&mut graph, &mut node_indices, &mapping.attack_object_id, NodeType::Mitre);

        let strength = calculate_strength(&mapping);
        graph.add_edge(veris_index, mitre_index, EdgeData {
            mapping_type: mapping.mapping_type.clone(),
            strength,
        });
    }

    Ok((graph, node_indices))
}

fn perform_analyses(graph: &MappingGraph, mappings: &[Mapping], node_indices: &HashMap<String, NodeIndex>) -> Result<AnalysisResults> {
    Ok(AnalysisResults {
        basic_stats: perform_basic_stats(graph, mappings),
        mapping_type_analysis: perform_mapping_type_analysis(graph),
        node_degree_analysis: perform_node_degree_analysis(graph),
        connected_components_analysis: perform_connected_components_analysis(graph),
        shortest_path_analysis: perform_shortest_path_analysis(graph, node_indices),
        edge_strength_analysis: perform_edge_strength_analysis(graph),
        node_type_distribution: perform_node_type_distribution(graph),
        temporal_analysis: perform_temporal_analysis(mappings),
        tech_domain_analysis: perform_tech_domain_analysis(mappings),
    })
}

fn export_results(analyses: &AnalysisResults) -> Result<()> {
    let output_dir = Path::new("./analysed/data");
    fs::create_dir_all(output_dir)?;

    for (name, data) in analyses.iter() {
        let file = File::create(output_dir.join(format!("{}.json", name)))?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, data)?;
    }

    Ok(())
}

fn export_combined_data(mappings: &[Mapping], node_degree_analysis: &serde_json::Value) -> Result<()> {
    let combined_data = prepare_combined_data(mappings, node_degree_analysis);

    // Pre-allocate vectors for DataFrame creation
    let mut veris_ids = Vec::with_capacity(combined_data.len());
    let mut mitre_ids = Vec::with_capacity(combined_data.len());
    let mut mapping_types = Vec::with_capacity(combined_data.len());
    let mut strengths = Vec::with_capacity(combined_data.len());
    let mut frequencies = Vec::with_capacity(combined_data.len());
    let mut impact_scores = Vec::with_capacity(combined_data.len());
    let mut tech_domains = Vec::with_capacity(combined_data.len());
    let mut creation_dates = Vec::with_capacity(combined_data.len());

    for row in &combined_data {
        veris_ids.push(row["veris_id"].as_str().unwrap());
        mitre_ids.push(row["mitre_id"].as_str().unwrap());
        mapping_types.push(row["mapping_type"].as_str().unwrap());
        strengths.push(row["strength"].as_f64().unwrap());
        frequencies.push(row["frequency"].as_u64().unwrap() as i32);
        impact_scores.push(row["impact_score"].as_f64().unwrap());
        tech_domains.push(row["technology_domain"].as_str().unwrap());
        creation_dates.push(row["creation_date"].as_str().unwrap());
    }

    let df = DataFrame::new(vec![
        Series::new("veris_id", veris_ids),
        Series::new("mitre_id", mitre_ids),
        Series::new("mapping_type", mapping_types),
        Series::new("strength", strengths),
        Series::new("frequency", frequencies),
        Series::new("impact_score", impact_scores),
        Series::new("technology_domain", tech_domains),
        Series::new("creation_date", creation_dates),
    ])?;

    // Export to Parquet
    let file = File::create("./analysed/data/combined_analysis.parquet")?;
    ParquetWriter::new(file).finish(&df)?;

    // Export to CSV
    let file = File::create("./analysed/ds/combined_analysis.csv")?;
    CsvWriter::new(file).finish(&df)?;

    Ok(())
}