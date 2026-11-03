//! Deterministic property tests for DNS, OID, and CN matching rules.

mod common;

use chainkeeper_core::San;
use chainkeeper_policy::{Oid, validate_dns_name};

/// Small xorshift generator so property runs are reproducible and dependency
/// free.
struct Rng(u64);

impl Rng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    const fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.0 = value;
        value.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn next_u32(&mut self) -> u32 {
        u32::try_from(self.next_u64() >> 32).expect("shifted value fits in u32")
    }

    fn below(&mut self, bound: u32) -> u32 {
        self.next_u32() % bound
    }

    fn range(&mut self, low: usize, high: usize) -> usize {
        let width = u32::try_from(high - low + 1).expect("range fits in u32");
        let offset = usize::try_from(self.below(width)).expect("offset fits in usize");
        low + offset
    }
}

const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

fn random_label(rng: &mut Rng) -> String {
    let len = rng.range(1, 20);
    let mut label = String::with_capacity(len);
    for _ in 0..len {
        let index = usize::try_from(rng.below(u32::try_from(ALPHABET.len()).expect("fits")))
            .expect("index fits");
        label.push(char::from(ALPHABET[index]));
    }
    label
}

fn random_dns_name(rng: &mut Rng) -> String {
    let labels = rng.range(1, 4);
    let mut name = String::new();
    for index in 0..labels {
        if index > 0 {
            name.push('.');
        }
        name.push_str(&random_label(rng));
    }
    name
}

#[test]
fn generated_valid_dns_names_always_parse() {
    let mut rng = Rng::new(0x5EED_1234);
    for _ in 0..512 {
        let name = random_dns_name(&mut rng);
        assert!(validate_dns_name(&name, false).is_ok(), "{name:?}");
    }
}

#[test]
fn dns_names_with_spaces_or_empty_labels_always_fail() {
    let mut rng = Rng::new(0xC0FF_EE01);
    for _ in 0..512 {
        let name = random_dns_name(&mut rng);

        let mut spaced = name.clone();
        let position = rng.range(0, spaced.len() - 1);
        spaced.insert(position, ' ');
        assert!(validate_dns_name(&spaced, false).is_err(), "{spaced:?}");

        let empty_label = format!("{name}..");
        assert!(
            validate_dns_name(&empty_label, false).is_err(),
            "{empty_label:?}"
        );
    }
}

#[test]
fn generated_oids_round_trip() {
    let mut rng = Rng::new(0x0D1_2D1D);
    for _ in 0..512 {
        let first = rng.below(3);
        let second = if first < 2 {
            rng.below(40)
        } else {
            rng.below(1000)
        };
        let mut oid = format!("{first}.{second}");
        let extra_arcs = rng.range(0, 5);
        for _ in 0..extra_arcs {
            oid.push('.');
            oid.push_str(&rng.below(100_000).to_string());
        }

        let parsed = Oid::parse(&oid).expect("generated OID is valid");
        assert_eq!(parsed.to_string(), oid);
    }
}

#[test]
fn oids_with_leading_zeros_always_fail() {
    let mut rng = Rng::new(0xBAD_0D1D);
    for _ in 0..512 {
        let first = rng.below(3);
        let second = rng.below(1000);
        let oid = format!("0{first}.{second}");
        assert!(Oid::parse(&oid).is_err(), "{oid:?}");
    }
}

#[test]
fn cn_equal_to_a_dns_san_always_validates() {
    let mut rng = Rng::new(0x600D_5A4D);
    let policy = common::base_policy();
    let profile = common::builtin("tls-server");
    for _ in 0..256 {
        let name = random_dns_name(&mut rng);
        let request = common::dns_request("tls-server", &name);
        common::validate(&policy, &profile, &request).expect("CN matches the DNS SAN");
    }
}

#[test]
fn cn_differing_from_every_san_always_fails() {
    let mut rng = Rng::new(0xDEAD_5A4D);
    let policy = common::base_policy();
    let profile = common::builtin("tls-server");
    for _ in 0..256 {
        let name = random_dns_name(&mut rng);
        let request = common::request_with(
            "tls-server",
            &format!("different-{name}"),
            vec![San::Dns(name)],
        );
        assert!(common::validate(&policy, &profile, &request).is_err());
    }
}
