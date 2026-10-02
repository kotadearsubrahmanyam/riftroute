use crate::relay::models::{PathDiversityResult, PathDiversityType};

/// Engine analyzing route structure and transit diversity between direct and relay paths (Step 19 & 20).
pub struct DiversityEngine;

impl DiversityEngine {
    /// Evaluate path diversity between direct path and relay path legs.
    pub fn evaluate_diversity(
        direct_fingerprint: &str,
        direct_hop_count: usize,
        leg1_fingerprint: &str,
        leg2_fingerprint: &str,
        leg2_hop_count: usize,
    ) -> PathDiversityResult {
        if direct_fingerprint.is_empty() || leg2_fingerprint.is_empty() {
            return PathDiversityResult {
                diversity_type: PathDiversityType::InsufficientEvidence,
                direct_fingerprint: direct_fingerprint.to_string(),
                leg1_fingerprint: leg1_fingerprint.to_string(),
                leg2_fingerprint: leg2_fingerprint.to_string(),
                direct_hop_count,
                relay_hop_count: leg2_hop_count,
                shared_hops_count: 0,
                distinct_hops_count: direct_hop_count + leg2_hop_count,
                rationale: "Insufficient route fingerprint data to evaluate path diversity".to_string(),
            };
        }

        if direct_fingerprint == leg2_fingerprint {
            return PathDiversityResult {
                diversity_type: PathDiversityType::SameObservedPath,
                direct_fingerprint: direct_fingerprint.to_string(),
                leg1_fingerprint: leg1_fingerprint.to_string(),
                leg2_fingerprint: leg2_fingerprint.to_string(),
                direct_hop_count,
                relay_hop_count: leg2_hop_count,
                shared_hops_count: direct_hop_count,
                distinct_hops_count: 0,
                rationale: "Identical route fingerprints observed between direct path and relay egress leg".to_string(),
            };
        }

        // Check if difference is purely minor variation or full structural variation
        let hop_diff = (direct_hop_count as isize - leg2_hop_count as isize).abs();
        if hop_diff == 0 && direct_hop_count > 0 {
            // Same hop count but different hash -> could be minor or structural
            PathDiversityResult {
                diversity_type: PathDiversityType::StructuralRouteVariation,
                direct_fingerprint: direct_fingerprint.to_string(),
                leg1_fingerprint: leg1_fingerprint.to_string(),
                leg2_fingerprint: leg2_fingerprint.to_string(),
                direct_hop_count,
                relay_hop_count: leg2_hop_count,
                shared_hops_count: 0,
                distinct_hops_count: direct_hop_count,
                rationale: format!(
                    "Path divergence detected: Direct '{}' vs Relay Leg '{}' with same hop count ({})",
                    direct_fingerprint, leg2_fingerprint, direct_hop_count
                ),
            }
        } else {
            PathDiversityResult {
                diversity_type: PathDiversityType::StructuralRouteVariation,
                direct_fingerprint: direct_fingerprint.to_string(),
                leg1_fingerprint: leg1_fingerprint.to_string(),
                leg2_fingerprint: leg2_fingerprint.to_string(),
                direct_hop_count,
                relay_hop_count: leg2_hop_count,
                shared_hops_count: 0,
                distinct_hops_count: (direct_hop_count + leg2_hop_count),
                rationale: format!(
                    "Structural route variation: Direct ({} hops, fp '{}') vs Relay ({} hops, fp '{}')",
                    direct_hop_count, direct_fingerprint, leg2_hop_count, leg2_fingerprint
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diversity_same_path() {
        let res = DiversityEngine::evaluate_diversity("ABC12345", 5, "LEG1FP", "ABC12345", 5);
        assert_eq!(res.diversity_type, PathDiversityType::SameObservedPath);
    }

    #[test]
    fn test_diversity_structural_variation() {
        let res = DiversityEngine::evaluate_diversity("ABC12345", 6, "LEG1FP", "XYZ98765", 4);
        assert_eq!(res.diversity_type, PathDiversityType::StructuralRouteVariation);
    }

    #[test]
    fn test_diversity_insufficient_evidence() {
        let res = DiversityEngine::evaluate_diversity("", 0, "LEG1FP", "XYZ98765", 4);
        assert_eq!(res.diversity_type, PathDiversityType::InsufficientEvidence);
    }
}
