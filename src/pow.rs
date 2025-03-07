use hmac::{Hmac, Mac};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub fn generate_pow_challenge_buffer(
    ip: &IpAddr,
    user_agent: &str,
    pow_manager: &PowManager,
    initial_hardness: u8,
    second_hardness: u8,
) -> Vec<u8> {
    let mut buffer = Vec::new();

    let initial_challenge = pow_manager.generate_challenge(&ip, user_agent, initial_hardness);
    buffer.extend_from_slice(&initial_challenge.nonce);
    buffer.extend_from_slice(&initial_challenge.timestamp.to_be_bytes());
    buffer.push(initial_challenge.hardness);
    buffer.extend_from_slice(&initial_challenge.signature);

    let second_challenge = pow_manager.generate_challenge(&ip, user_agent, second_hardness);
    buffer.extend_from_slice(&second_challenge.nonce);
    buffer.extend_from_slice(&second_challenge.timestamp.to_be_bytes());
    buffer.push(second_challenge.hardness);
    buffer.extend_from_slice(&second_challenge.signature);

    buffer
}

#[derive(Debug)]
pub struct ParsedChallenge {
    pub nonce: [u8; 16],
    pub timestamp: u64,
    pub hardness: u8,
    pub signature: Vec<u8>,
    pub solution: Vec<u8>,
}

pub fn parse_pow_solution_buffer(data: &[u8]) -> Result<ParsedChallenge, &'static str> {
    if data.len() != 65 {
        return Err("Buffer too small");
    }

    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&data[..16]);

    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&data[16..24]);
    let timestamp = u64::from_be_bytes(timestamp_bytes);

    let hardness = data[24];

    let signature = data[25..57].to_vec();

    let solution = data[57..].to_vec();

    Ok(ParsedChallenge {
        nonce,
        timestamp,
        hardness,
        signature,
        solution,
    })
}

#[derive(Clone, Debug)]
pub struct PowChallenge {
    pub nonce: [u8; 16],
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub hardness: u8,
}

pub struct PowManager {
    secret_token: [u8; 32],
}

impl PowManager {
    pub fn new() -> Self {
        let mut secret_token = [0u8; 32];
        thread_rng().fill(&mut secret_token);

        Self { secret_token }
    }

    pub fn with_secret(secret_token: [u8; 32]) -> Self {
        Self { secret_token }
    }

    pub fn get_secret(&self) -> [u8; 32] {
        self.secret_token
    }

    fn generate_signature(
        &self,
        nonce: &[u8],
        timestamp: u64,
        ip: &IpAddr,
        user_agent: &str,
    ) -> Vec<u8> {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret_token).expect("HMAC can take key of any size");

        mac.update(nonce);
        mac.update(&timestamp.to_be_bytes());
        mac.update(ip.to_string().as_bytes());
        mac.update(user_agent.as_bytes());

        mac.finalize().into_bytes().to_vec()
    }

    pub fn generate_challenge(&self, ip: &IpAddr, user_agent: &str, hardness: u8) -> PowChallenge {
        let mut nonce = [0u8; 16];
        thread_rng().fill(&mut nonce);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let signature = self.generate_signature(&nonce, timestamp, ip, user_agent);

        PowChallenge {
            nonce,
            timestamp,
            signature,
            hardness,
        }
    }

    pub fn verify_challenge_validity(
        &self,
        challenge: &PowChallenge,
        ip: &IpAddr,
        user_agent: &str,
        expiry_seconds: u64,
    ) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        if current_time > challenge.timestamp + expiry_seconds {
            return false;
        }

        let expected_signature =
            self.generate_signature(&challenge.nonce, challenge.timestamp, ip, user_agent);

        challenge.signature == expected_signature
    }

    pub fn verify_solution(&self, challenge: &PowChallenge, solution: &[u8]) -> bool {
        let mut hasher = Sha256::new();

        hasher.update(&challenge.nonce);
        hasher.update(&challenge.timestamp.to_be_bytes());
        hasher.update(&challenge.signature);
        hasher.update(solution);

        let hash = hasher.finalize();

        for i in 0..challenge.hardness {
            let byte_idx = (i / 8) as usize;
            let bit_idx = 7 - (i % 8);

            if byte_idx >= hash.len() {
                return false;
            }

            let bit = (hash[byte_idx] >> bit_idx) & 1;
            if bit != 0 {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
pub fn solve_challenge(challenge: &PowChallenge) -> Vec<u8> {
    let mut solution = [0u8; 8];
    let mut counter: u64 = 0;

    loop {
        counter += 1;
        solution.copy_from_slice(&counter.to_be_bytes());

        let mut hasher = Sha256::new();
        hasher.update(&challenge.nonce);
        hasher.update(&challenge.timestamp.to_be_bytes());
        hasher.update(&challenge.signature);
        hasher.update(&solution);

        let hash = hasher.finalize();

        let mut valid = true;

        for i in 0..challenge.hardness {
            let byte_idx = (i / 8) as usize;
            let bit_idx = 7 - (i % 8);

            let bit = (hash[byte_idx] >> bit_idx) & 1;
            if bit != 0 {
                valid = false;
                break;
            }
        }

        if valid {
            return solution.to_vec();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread;
    use std::time::Duration;

    fn setup_test_env() -> (PowManager, IpAddr, String) {
        let secret = [42u8; 32];
        let pow_manager = PowManager::with_secret(secret);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let user_agent = "test_browser/1.0".to_string();
        (pow_manager, ip, user_agent)
    }

    #[test]
    fn test_pow_manager_creation() {
        let secret = [42u8; 32];
        let pow_manager = PowManager::with_secret(secret);
        assert_eq!(pow_manager.get_secret(), secret);

        let pow_manager = PowManager::new();
        assert_ne!(pow_manager.get_secret(), [0u8; 32]);
    }

    #[test]
    fn test_challenge_generation() {
        let (pow_manager, ip, user_agent) = setup_test_env();
        let hardness = 8;

        let challenge = pow_manager.generate_challenge(&ip, &user_agent, hardness);

        assert_eq!(challenge.hardness, hardness);
        assert!(!challenge.nonce.iter().all(|&x| x == 0));
        assert!(!challenge.signature.is_empty());
    }

    #[test]
    fn test_challenge_validity() {
        let (pow_manager, ip, user_agent) = setup_test_env();
        let hardness = 8;
        let expiry_seconds = 60;

        let challenge = pow_manager.generate_challenge(&ip, &user_agent, hardness);

        assert!(pow_manager.verify_challenge_validity(
            &challenge,
            &ip,
            &user_agent,
            expiry_seconds
        ));

        let wrong_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(!pow_manager.verify_challenge_validity(
            &challenge,
            &wrong_ip,
            &user_agent,
            expiry_seconds
        ));

        assert!(!pow_manager.verify_challenge_validity(
            &challenge,
            &ip,
            "wrong_agent",
            expiry_seconds
        ));

        thread::sleep(Duration::from_secs(1));
        assert!(!pow_manager.verify_challenge_validity(&challenge, &ip, &user_agent, 0));
    }

    #[test]
    fn test_solution_verification() {
        let (pow_manager, ip, user_agent) = setup_test_env();
        let hardness = 8;

        let challenge = pow_manager.generate_challenge(&ip, &user_agent, hardness);
        let solution = solve_challenge(&challenge);

        assert!(pow_manager.verify_solution(&challenge, &solution));

        let invalid_solution = vec![0u8; 8];
        assert!(!pow_manager.verify_solution(&challenge, &invalid_solution));
    }

    #[test]
    fn test_pow_challenge_buffer() {
        let (pow_manager, ip, user_agent) = setup_test_env();
        let initial_hardness = 8;
        let second_hardness = 12;

        let buffer = generate_pow_challenge_buffer(
            &ip,
            &user_agent,
            &pow_manager,
            initial_hardness,
            second_hardness,
        );

        assert_eq!(buffer.len(), 2 * (16 + 8 + 1 + 32));
    }

    #[test]
    fn test_parse_pow_solution() {
        let mut test_buffer = Vec::new();

        test_buffer.extend_from_slice(&[1u8; 16]); // nonce
        test_buffer.extend_from_slice(&42u64.to_be_bytes()); // timestamp
        test_buffer.push(8); // hardness
        test_buffer.extend_from_slice(&[2u8; 32]); // signature
        test_buffer.extend_from_slice(&[3u8; 8]); // solution

        let result = parse_pow_solution_buffer(&test_buffer).unwrap();

        assert_eq!(result.nonce, [1u8; 16]);
        assert_eq!(result.timestamp, 42);
        assert_eq!(result.hardness, 8);
        assert_eq!(result.signature, vec![2u8; 32]);
        assert_eq!(result.solution, vec![3u8; 8]);
    }

    #[test]
    fn test_parse_pow_solution_invalid_size() {
        let invalid_buffer = vec![0u8; 64];
        assert!(parse_pow_solution_buffer(&invalid_buffer).is_err());
    }

    #[test]
    fn test_complete_pow_workflow() {
        let (pow_manager, ip, user_agent) = setup_test_env();
        let hardness = 8;

        let challenge = pow_manager.generate_challenge(&ip, &user_agent, hardness);
        assert!(pow_manager.verify_challenge_validity(&challenge, &ip, &user_agent, 60));

        let solution = solve_challenge(&challenge);
        assert!(pow_manager.verify_solution(&challenge, &solution));
    }
}
