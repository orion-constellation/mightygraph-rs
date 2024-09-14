use super::*;
use serde_json::json;
use std::fs::File;
use std::io::Read;
use polars::prelude::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_successful_combination_of_data() {
        let mappings = vec![
            Mapping {
                veris_id: "V1".to_string(),
                mitre_id: "M1".to_string(),
                mapping_type: "type1".to_string(),
                strength: 0.8,
                frequency: 10,
                impact_score: 5.0,
                technology_domain: "domain1".to_string(),
                creation_date: "2023-01-01".to_string(),
            },
            Mapping {
                veris_id: "V2".to_string(),
                mitre_id: "M2".to_string(),
                mapping_type: "type2".to_string(),
                strength: 0.9,
                frequency: 20,
                impact_score: 6.0,
                technology_domain: "domain2".to_string(),
                creation_date: "2023-01-02".to_string(),
            },
        ];
        
        let node_degree_analysis = json!({
            "some_key": "some_value"
        });
        
        let result = export_combined_data(&mappings, &node_degree_analysis);
        assert!(result.is_ok());
        
        let mut file = File::open("./analysed/data/combined_analysis.parquet").unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();
        assert!(!buffer.is_empty());
        
        let mut file = File::open("./analysed/ds/combined_analysis.csv").unwrap();
        let mut buffer = String::new();
        file.read_to_string(&mut buffer).unwrap();
        assert!(!buffer.is_empty());
    }

    use serde_json::json;
    use std::fs::File;
    use std::io::Read;
    use polars::prelude::*;

    #[test]
    fn test_empty_mappings_and_node_degree_analysis() {
        let mappings = vec![];
        
        let node_degree_analysis = json!({});
        
        let result = export_combined_data(&mappings, &node_degree_analysis);
        assert!(result.is_ok());
        
        let mut file = File::open("./analysed/data/combined_analysis.parquet").unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();
        assert!(buffer.is_empty());
        
        let mut file = File::open("./analysed/ds/combined_analysis.csv").unwrap();
        let mut buffer = String::new();
        file.read_to_string(&mut buffer).unwrap();
        assert!(buffer.is_empty());
    }

    use std::fs::File;
    use std::path::Path;
    use serde_json::json;
    use crate::petgraph_full_0x0::prelude::*;

    #[test]
    fn test_export_combined_data_to_parquet() {
        let mappings = vec![
            Mapping {
                veris_id: "V1".to_string(),
                mitre_id: "M1".to_string(),
                mapping_type: "type1".to_string(),
                strength: 0.8,
                frequency: 5,
                impact_score: 3.2,
                technology_domain: "domain1".to_string(),
                creation_date: "2023-01-01".to_string(),
            },
        ];
        
        let node_degree_analysis = json!({
            "node1": {"degree": 3},
            "node2": {"degree": 5}
        });
        
        let result = export_combined_data(&mappings, &node_degree_analysis);
        assert!(result.is_ok());
        
        let path = Path::new("./analysed/data/combined_analysis.parquet");
        assert!(path.exists());
    }

}