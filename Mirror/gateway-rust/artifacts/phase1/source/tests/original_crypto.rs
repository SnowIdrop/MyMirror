// Author: MingTea. Actual original-003 export, synthetic credentials only.
use mirror_gateway::crypto::Crypto;
#[test]
fn decrypts_original_observed_session_credential() {
    let crypto = Crypto::new("contract-encryption-key-000000000000001").unwrap();
    let cipher = "enc:v1:hp_VzOEc1VjLBMz4jrmfgtcSwl2FvRgIXJvbPYW0Htl2jJQNKosu1tYPlSRFIM9N_rk";
    assert_eq!(crypto.decrypt(cipher).unwrap(), "synthetic-access-token");
    let empty = "enc:v1:GkLazFj5AW9oBMPyJIVRbiSTKyWpdXuOpndBhJYW";
    assert_eq!(crypto.decrypt(empty).unwrap(), "[]");
}
