pub fn add_node_if_not_exists(
    graph: &mut MappingGraph,
    node_indices: &mut HashMap<String, NodeIndex>,
    id: &str,
    node_type: NodeType
) -> NodeIndex {
    if let Some(&index) = node_indices.get(id) {
        return index;
    }

    let node_data = NodeData {
        id: id.to_string(),
        node_type,
        metadata: HashMap::new(),
    };

    let index = graph.add_node(node_data);
    node_indices.insert(id.to_string(), index);
    index
}

/// Calculates the strength of a mapping based on certain criteria.
/// 
/// # Arguments
/// 
/// - `mapping`: A reference to a `Mapping` object.
/// 
/// # Returns
/// 
/// - `f32`: The strength of the mapping.
pub fn calculate_strength(mapping: &Mapping) -> f32 {
    // Example calculation based on arbitrary logic; adapt as needed
    match mapping.mapping_type.as_str() {
        "Strong" => 1.0,
        "Moderate" => 0.7,
        "Weak" => 0.4,
        _ => 0.1,
    }
}

/// Prepares combined data for export based on mappings and node degree analysis.
/// 
/// # Arguments
/// 
/// - `mappings`: A slice of `Mapping` structs containing the data to be exported.
/// - `node_degree_analysis`: A serde_json Value representing the node degree analysis data.
/// 
/// # Returns
/// 
/// - `Vec<serde_json::Value>`: A vector of JSON values containing the combined data.
pub fn prepare_combined_data(
    mappings: &[Mapping],
    node_degree_analysis: &serde_json::Value
) -> Vec<serde_json::Value> {
    let mut combined_data = vec![];

    for mapping in mappings {
        let frequency = node_degree_analysis.get(&mapping.attack_object_id).unwrap_or(&Value).as_i64().unwrap_or(0);
        let strength = calculate_strength(mapping);
        let impact_score = (frequency as f32 * strength) / 10.0; // Normalize to 0-10 scale

        combined_data.push(serde_json::json({
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
    
    combined_data
}