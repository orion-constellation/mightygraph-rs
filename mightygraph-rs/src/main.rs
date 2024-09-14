//! # VERIS-MITRE Mapping Analysis Tool
//!
//! This binary program uses the `petgraph_full_0x0` library to perform graph-based
//! analyses on the relationships between VERIS and MITRE ATT&CK frameworks. The tool
//! loads data from a CSV file, constructs a graph, performs a variety of analyses, and
//! exports the results in JSON, CSV, and Parquet formats.
//!
//! The program executes the following major steps:
//!
//! 1. **Load Data**: Reads mappings from a CSV file that describes the relationship
//!    between VERIS and MITRE ATT&CK objects. Each mapping contains metadata about
//!    the mapping strength, type, and associated data.
//!
//! 2. **Graph Creation**: Builds a graph where each node represents either a VERIS or
//!    MITRE object, and edges represent mappings between these nodes.
//!
//! 3. **Graph Analysis**: The program performs a variety of analyses on the graph, including:
//!    - Node degree analysis
//!    - Shortest path analysis
//!    - Connected components analysis
//!    - Edge strength analysis
//!
//! 4. **Export Results**: The results of the analyses are exported to different formats
//!    including JSON, CSV, and Parquet for easy reporting and further analysis.
//!
//! ## Usage
//!
//! The program expects a CSV file as input, containing the mappings between VERIS and
//! MITRE objects. The data is loaded, analyzed, and results are saved in an output
//! directory.
//!
//! ```bash
//! $ cargo run --release
//! ```
//!
//! ## Example Workflow
//!
//! 1. Load the CSV data.
//! 2. Create the graph and add nodes and edges.
//! 3. Perform analyses like node degree, shortest path, and connected components analysis.
//! 4. Export results to JSON, CSV, and Parquet formats.
//!
//! ## Output Files
//!
//! The output is saved in an `analysed/data/` directory, containing files such as:
//! - `combined_analysis.csv`: Combined data exported in CSV format.
//! - `combined_analysis.parquet`: Combined data exported in Parquet format.
//! - Individual JSON files for each type of analysis.
//!
//! ## Example Code
//!
//! ```rust
//! fn main() -> Result<()> {
//!     // Load CSV data and build graph
//!     let mappings = load_csv_data("path/to/csv")?;
//!     let (graph, node_indices) = create_graph(&mappings)?;
//!
//!     // Perform analyses
//!     let analyses = perform_analyses(&graph, &mappings, &node_indices)?;
//!
//!     // Export the results
//!     export_results(&analyses)?;
//!     export_combined_data(&mappings, &analyses.node_degree_analysis)?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## External Crates Used
//!
//! - `petgraph`: For graph data structures and algorithms.
//! - `polars`: For exporting data to Parquet and CSV formats.
//! - `serde`, `serde_json`: For JSON serialization.
//! - `csv`: For CSV data parsing and export.
//!
// Declare the external modules
pub mod petgraph_full_0x0;
pub mod utils;

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::Path;
use petgraph::graph::{Graph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde_json::json;
use polars::prelude::ParquetWriter;
use csv;

// Import specific utility functions from utils
use utils::*;

// Import structures and types from petgraph_full_0x0
use petgraph_full_0x0::{ Mapping, NodeData, NodeType, MappingGraph, EdgeData, MappingGraph, export_combined_data, export_node_degree_analysis, main };
use petgraph_full_0x0::{ create_graph, perform_analyses };


// Structures definitions remain the same

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;


/// Main function to load CSV data, create a graph, perform analyses, and export results to JSON, Parquet, and CSV.
/// 
/// # Returns
/// 
/// - `Result<()>`: Indicates the success or failure of the main process.
fn main() -> Result<()> {
    // 1. Load the CSV data
    static csv_file: &str = "/Users/nullzero/Documents/repos/opencti/veris_mitre_map/veris_mitre_map/data /veris-1.3.7_attack-12.1-enterprise.csv";
    let file = File::open(csv_file)?;
    let reader = BufReader::new(file);
    let mut rdr = csv::Reader::from_reader(reader);
    let mappings: Vec<Mapping> = rdr.deserialize().collect::<dyn Result<_, Error>>()?;

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



/// Creates a graph based on the provided mappings.
/// 
/// # Arguments
///  `mappings` - A slice of `Mapping` structs containing the data for creating the graph.
/// 
/// # Returns
/// A tuple containing the created `MappingGraph` and a `HashMap` with node indices.
/// 
/// # Errors
/// Returns an error if there are issues during the graph creation process.
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


/// Performs various analyses on the provided graph using the mappings and node indices.
/// Returns the results of the analyses including basic statistics, mapping type analysis,
/// node degree analysis, connected components analysis, shortest path analysis, edge strength analysis,
/// node type distribution, temporal analysis, and tech domain analysis.
/// 
/// # Arguments
/// - `graph`: A reference to the MappingGraph on which the analyses are performed.
/// - `mappings`: An array of Mapping structs used for analysis.
/// - `node_indices`: A HashMap containing node indices for efficient analysis.
/// 
/// # Returns
/// A Result containing the AnalysisResults struct with the results of the performed analyses.
fn perform_analyses(graph: &MappingGraph, mappings: &[Mapping], node_indices: &HashMap<String, NodeIndex>) -> Result<AnalysisResults> {
    Ok(AnalysisResults {
        basic_stats: perform_basic_stats(graph, mappings),
        mapping_type_analysis: perform_mapping_type_analysis(graph),
        node_degree_analysis: perform_node_degree_analysis(graph),
        connected_components_analysis: perform_connected_components_analysis(graph),
        shortest_path_analysis: perform_shortest_path_analysis(graph, node_indices),
        edge_strength_analysis: perform_edge_strength_analysis(graph),
        node_type_distribution: perform_node_type_distribution(graph),
        utils::calculate_strength: perform_node_type_distribution(graph),
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


/// Export combined data to Parquet and CSV formats based on mappings and node degree analysis.
/// 
/// # Arguments
///  `mappings` - A slice of Mapping structs containing the data to be exported.
/// `node_degree_analysis` - A serde_json Value representing the node degree analysis data.
/// 
/// # Returns
/// A Result indicating success or an error if the export fails.
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
    CsvWriter::new(file).finish(&mut df)?;

    Ok(())
}