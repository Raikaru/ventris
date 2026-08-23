//! Deterministic, evidence-carrying semantic comparisons.
//!
//! Comparisons operate on normalized facts rather than compiler-specific text.
//! Unsupported and unavailable observations remain distinct from divergences.

use std::collections::BTreeMap;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SemanticDimension {
    Boundary,
    ControlFlow,
    Calls,
    Globals,
    RecoveredAccessesTypes,
    Casts,
    AggregateCopies,
    DeclarationOrder,
    SourceStructure,
    NominalFields,
}

impl SemanticDimension {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Boundary => "boundary",
            Self::ControlFlow => "control_flow",
            Self::Calls => "calls",
            Self::Globals => "globals",
            Self::RecoveredAccessesTypes => "recovered_accesses_types",
            Self::Casts => "casts",
            Self::AggregateCopies => "aggregate_copies",
            Self::DeclarationOrder => "declaration_order",
            Self::SourceStructure => "reconstructed_source_structure",
            Self::NominalFields => "nominal_fields",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticValue {
    Boundary { address: u64, size: u32 },
    Set(Vec<String>),
    Sequence(Vec<String>),
    Count(u32),
}

impl SemanticValue {
    pub fn set(values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let mut values = values.into_iter().map(Into::into).collect::<Vec<_>>();
        values.sort();
        values.dedup();
        Self::Set(values)
    }

    pub fn sequence(values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::Sequence(values.into_iter().map(Into::into).collect())
    }

    fn normalized(mut self) -> Self {
        if let Self::Set(values) = &mut self {
            values.sort();
            values.dedup();
        }
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticExpectation {
    pub dimension: SemanticDimension,
    pub value: SemanticValue,
    pub provenance: String,
}

impl SemanticExpectation {
    pub fn new(
        dimension: SemanticDimension,
        value: SemanticValue,
        provenance: impl Into<String>,
    ) -> Self {
        Self {
            dimension,
            value: value.normalized(),
            provenance: provenance.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservationAvailability {
    Available(SemanticValue),
    /// A value produced after applying explicit source metadata. This is
    /// successful evidence, but it must not be reported as machine-derived.
    Applied(SemanticValue),
    Unsupported(String),
    Unavailable(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticObservation {
    pub dimension: SemanticDimension,
    pub availability: ObservationAvailability,
    pub provenance: String,
}

impl SemanticObservation {
    pub fn available(
        dimension: SemanticDimension,
        value: SemanticValue,
        provenance: impl Into<String>,
    ) -> Self {
        Self {
            dimension,
            availability: ObservationAvailability::Available(value.normalized()),
            provenance: provenance.into(),
        }
    }

    pub fn applied(
        dimension: SemanticDimension,
        value: SemanticValue,
        provenance: impl Into<String>,
    ) -> Self {
        Self {
            dimension,
            availability: ObservationAvailability::Applied(value.normalized()),
            provenance: provenance.into(),
        }
    }

    pub fn unsupported(
        dimension: SemanticDimension,
        reason: impl Into<String>,
        provenance: impl Into<String>,
    ) -> Self {
        Self {
            dimension,
            availability: ObservationAvailability::Unsupported(reason.into()),
            provenance: provenance.into(),
        }
    }

    pub fn unavailable(
        dimension: SemanticDimension,
        reason: impl Into<String>,
        provenance: impl Into<String>,
    ) -> Self {
        Self {
            dimension,
            availability: ObservationAvailability::Unavailable(reason.into()),
            provenance: provenance.into(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SemanticStatus {
    Exact,
    Applied,
    Diverged,
    Unsupported,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticDimensionResult {
    pub dimension: SemanticDimension,
    pub status: SemanticStatus,
    pub expected: SemanticValue,
    pub observed: Option<SemanticValue>,
    pub expected_provenance: String,
    pub observed_provenance: Option<String>,
    pub detail: Option<String>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SemanticReportStatus {
    Exact,
    Diverged,
    Incomplete,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticReport {
    pub function: String,
    pub status: SemanticReportStatus,
    pub dimensions: Vec<SemanticDimensionResult>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticComparisonError {
    MissingExpectations,
    DuplicateExpectation(SemanticDimension),
    DuplicateObservation(SemanticDimension),
}

pub fn compare_semantics(
    function: impl Into<String>,
    expectations: impl IntoIterator<Item = SemanticExpectation>,
    observations: impl IntoIterator<Item = SemanticObservation>,
) -> Result<SemanticReport, SemanticComparisonError> {
    let mut expected_by_dimension = BTreeMap::new();
    for item in expectations {
        let dimension = item.dimension;
        if expected_by_dimension.insert(dimension, item).is_some() {
            return Err(SemanticComparisonError::DuplicateExpectation(dimension));
        }
    }
    if expected_by_dimension.is_empty() {
        return Err(SemanticComparisonError::MissingExpectations);
    }
    let mut observed_by_dimension = BTreeMap::new();
    for item in observations {
        let dimension = item.dimension;
        if observed_by_dimension.insert(dimension, item).is_some() {
            return Err(SemanticComparisonError::DuplicateObservation(dimension));
        }
    }

    let dimensions = expected_by_dimension
        .into_iter()
        .map(|(dimension, expectation)| {
            let Some(observation) = observed_by_dimension.get(&dimension) else {
                return SemanticDimensionResult {
                    dimension,
                    status: SemanticStatus::Unavailable,
                    expected: expectation.value,
                    observed: None,
                    expected_provenance: expectation.provenance,
                    observed_provenance: None,
                    detail: Some("observation not provided".into()),
                };
            };
            match &observation.availability {
                ObservationAvailability::Available(observed) => SemanticDimensionResult {
                    dimension,
                    status: if expectation.value == *observed {
                        SemanticStatus::Exact
                    } else {
                        SemanticStatus::Diverged
                    },
                    expected: expectation.value,
                    observed: Some(observed.clone()),
                    expected_provenance: expectation.provenance,
                    observed_provenance: Some(observation.provenance.clone()),
                    detail: None,
                },
                ObservationAvailability::Applied(observed) => SemanticDimensionResult {
                    dimension,
                    status: if expectation.value == *observed {
                        SemanticStatus::Applied
                    } else {
                        SemanticStatus::Diverged
                    },
                    expected: expectation.value,
                    observed: Some(observed.clone()),
                    expected_provenance: expectation.provenance,
                    observed_provenance: Some(observation.provenance.clone()),
                    detail: None,
                },
                ObservationAvailability::Unsupported(reason) => SemanticDimensionResult {
                    dimension,
                    status: SemanticStatus::Unsupported,
                    expected: expectation.value,
                    observed: None,
                    expected_provenance: expectation.provenance,
                    observed_provenance: Some(observation.provenance.clone()),
                    detail: Some(reason.clone()),
                },
                ObservationAvailability::Unavailable(reason) => SemanticDimensionResult {
                    dimension,
                    status: SemanticStatus::Unavailable,
                    expected: expectation.value,
                    observed: None,
                    expected_provenance: expectation.provenance,
                    observed_provenance: Some(observation.provenance.clone()),
                    detail: Some(reason.clone()),
                },
            }
        })
        .collect::<Vec<_>>();

    let status = if dimensions
        .iter()
        .all(|item| matches!(item.status, SemanticStatus::Exact | SemanticStatus::Applied))
    {
        SemanticReportStatus::Exact
    } else if dimensions
        .iter()
        .any(|item| item.status == SemanticStatus::Diverged)
    {
        SemanticReportStatus::Diverged
    } else {
        SemanticReportStatus::Incomplete
    };

    Ok(SemanticReport {
        function: function.into(),
        status,
        dimensions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expectation(dimension: SemanticDimension, value: SemanticValue) -> SemanticExpectation {
        SemanticExpectation::new(dimension, value, "source.c@abc123")
    }

    #[test]
    fn exact_sets_are_order_independent_and_evidence_is_retained() {
        let report = compare_semantics(
            "render",
            [expectation(
                SemanticDimension::Calls,
                SemanticValue::set(["b", "a", "a"]),
            )],
            [SemanticObservation::available(
                SemanticDimension::Calls,
                SemanticValue::set(["a", "b"]),
                "lifted p-code",
            )],
        )
        .unwrap();
        assert_eq!(report.status, SemanticReportStatus::Exact);
        assert_eq!(report.dimensions[0].status, SemanticStatus::Exact);
        assert_eq!(
            report.dimensions[0].observed_provenance.as_deref(),
            Some("lifted p-code")
        );
    }

    #[test]
    fn applied_source_metadata_is_successful_but_not_machine_exact() {
        let report = compare_semantics(
            "render",
            [expectation(
                SemanticDimension::NominalFields,
                SemanticValue::set(["GameWorld.fadeAlpha"]),
            )],
            [SemanticObservation::applied(
                SemanticDimension::NominalFields,
                SemanticValue::set(["GameWorld.fadeAlpha"]),
                "game_world.hpp@602441a",
            )],
        )
        .unwrap();
        assert_eq!(report.status, SemanticReportStatus::Exact);
        assert_eq!(report.dimensions[0].status, SemanticStatus::Applied);
        assert_eq!(
            report.dimensions[0].observed_provenance.as_deref(),
            Some("game_world.hpp@602441a")
        );
    }

    #[test]
    fn sequence_divergence_names_the_dimension() {
        let report = compare_semantics(
            "render",
            [expectation(
                SemanticDimension::DeclarationOrder,
                SemanticValue::sequence(["first", "second"]),
            )],
            [SemanticObservation::available(
                SemanticDimension::DeclarationOrder,
                SemanticValue::sequence(["second", "first"]),
                "reconstructed source",
            )],
        )
        .unwrap();
        assert_eq!(report.status, SemanticReportStatus::Diverged);
        assert_eq!(report.dimensions[0].dimension.name(), "declaration_order");
        assert_eq!(report.dimensions[0].status, SemanticStatus::Diverged);
    }

    #[test]
    fn unsupported_and_unavailable_are_not_false_divergences() {
        let report = compare_semantics(
            "render",
            [
                expectation(SemanticDimension::Casts, SemanticValue::Count(1)),
                expectation(SemanticDimension::AggregateCopies, SemanticValue::Count(0)),
            ],
            [SemanticObservation::unsupported(
                SemanticDimension::Casts,
                "opcode is not lifted",
                "native analysis",
            )],
        )
        .unwrap();
        assert_eq!(report.status, SemanticReportStatus::Incomplete);
        assert_eq!(report.dimensions[0].status, SemanticStatus::Unsupported);
        assert_eq!(report.dimensions[1].status, SemanticStatus::Unavailable);
    }

    #[test]
    fn missing_and_duplicate_expectations_are_rejected() {
        assert_eq!(
            compare_semantics("render", [], []),
            Err(SemanticComparisonError::MissingExpectations)
        );
        assert_eq!(
            compare_semantics(
                "render",
                [
                    expectation(SemanticDimension::Calls, SemanticValue::Count(1)),
                    expectation(SemanticDimension::Calls, SemanticValue::Count(2)),
                ],
                [],
            ),
            Err(SemanticComparisonError::DuplicateExpectation(
                SemanticDimension::Calls
            ))
        );
    }
}
