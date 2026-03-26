use tdf_iroh_s3::test_cli::iroh_client::parse_endpoint_id;

#[test]
fn test_parse_endpoint_id_invalid() {
    let result = parse_endpoint_id("invalidnodeid");
    assert!(result.is_err(), "Invalid ID should return error");
}
