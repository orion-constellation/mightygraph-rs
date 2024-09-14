#[cfg(test)]
mod tests {
    use super::*;



    #[test]
    fn test_load_csv_data_success() {
        use std::fs::File;
        use std::io::Write;
        use tempfile::tempdir;
        use csv::Writer;
        use serde::Serialize;

        #[derive(Serialize)]
        struct Mapping {
            capability_id: String,
            attack_object_id: String,
            mapping_type: String,
            technology_domain: String,
            creation_date: String,
        }

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("veris_mitre_mapping.csv");
        let mut file = File::create(&file_path).unwrap();

        let mut wtr = Writer::from_writer(file);
        wtr.serialize(Mapping {
            capability_id: "cap1".to_string(),
            attack_object_id: "att1".to_string(),
            mapping_type: "type1".to_string(),
            technology_domain: "domain1".to_string(),
            creation_date: "2023-01-01".to_string(),
        }).unwrap();
        wtr.flush().unwrap();

        let result = main();
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_empty_csv_file() {
        use std::fs::File;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("veris_mitre_mapping.csv");
        File::create(&file_path).unwrap();

        let result = main();
        assert!(result.is_err());
    }

    #[test]
    fn test_perform_various_analyses() {
        // Mock data
        let mappings = vec![
            Mapping {
                capability_id: "cap1".to_string(),
                attack_object_id: "att1".to_string(),
                mapping_type: "type1".to_string(),
                technology_domain: "domain1".to_string(),
                creation_date: "2023-01-01".to_string(),
            },
            Mapping {
                capability_id: "cap2".to_string(),
                attack_object_id: "att2".to_string(),
                mapping_type: "type2".to_string(),
                technology_domain: "domain2".to_string(),
                creation_date: "2023-02-02".to_string(),
            },
        ];

        // Call the main function
        let result = main();

        // Assertions
        assert!(result.is_ok());
        // Add more specific assertions based on the expected behavior of the analyses
    }

    #[test]
    fn test_export_analysis_results_to_json() {
        // Setup
        let basic_stats = BasicStats { /* mock data */ };
        let mapping_type_analysis = MappingTypeAnalysis { /* mock data */ };
        let node_degree_analysis = NodeDegreeAnalysis { /* mock data */ };
        let connected_components_analysis = ConnectedComponentsAnalysis { /* mock data */ };
        let shortest_path_analysis = ShortestPathAnalysis { /* mock data */ };
        let edge_strength_analysis = EdgeStrengthAnalysis { /* mock data */ };
        let node_type_distribution = NodeTypeDistribution { /* mock data */ };
        let temporal_analysis = TemporalAnalysis { /* mock data */ };
        let tech_domain_analysis = TechDomainAnalysis { /* mock data */ };

        // Call the function under test
        let result = main();

        // Assertions
        assert!(result.is_ok());
        // Add more assertions based on the expected behavior of exporting to JSON files
    }

    #[test]
    fn test_combine_and_export_to_parquet_and_csv() {
        // Mock mappings data
        let mappings = vec![
            Mapping {
                capability_id: "cap1".to_string(),
                attack_object_id: "att1".to_string(),
                mapping_type: "type1".to_string(),
                technology_domain: "domain1".to_string(),
                creation_date: "2023-01-01".to_string(),
            },
            Mapping {
                capability_id: "cap2".to_string(),
                attack_object_id: "att2".to_string(),
                mapping_type: "type2".to_string(),
                technology_domain: "domain2".to_string(),
                creation_date: "2023-02-02".to_string(),
            },
        ];

        // Call the main function
        let result = main();

        // Assert the result
        assert!(result.is_ok());
    }
}