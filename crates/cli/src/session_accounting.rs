//! Leased session projections of authoritative request accounting.

use crate::sessions::{SessionFile, SessionLease, SessionLeaseError};
use orbit_engine::retry::{DetailedAccountingCheckpoint, RetryPolicyBinding};
use orbit_engine::{
    AccountingBaseline, AccountingCheckpoint, AccountingKnownness, CompactionJournal, HistoryError,
    KnownPricedSubtotals, SpendAllowance, TurnOptions,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootOrigin {
    FreshCandidate,
    RestoredOrLegacy,
    ForkedThisInvocation,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildOrigin {
    CreatedThisInvocation,
    Resumed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FullCostStatus {
    Known,
    UnknownLegacy,
    UnknownUsage,
    Uncertain,
    Unpriced,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAccountingWatermark {
    pub owner_session_id: String,
    pub child_id: Option<String>,
    pub revision: u64,
    pub known_input_tokens: u64,
    pub known_output_tokens: u64,
    pub known_ordinary_microcents: u64,
    pub known_housekeeping_microcents: u64,
    pub full_cost_status: FullCostStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceSpendPolicy {
    pub maximum_microcents: u64,
    pub allow_unpriced_housekeeping: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountingView {
    pub revision: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub known_cost_microcents: u64,
    pub full_cost_status: FullCostStatus,
}

#[derive(Debug)]
pub enum AccountingError {
    History(HistoryError),
    Session(SessionLeaseError),
    InvalidState(&'static str),
    SpendRefused(&'static str),
}
impl std::fmt::Display for AccountingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::History(HistoryError::Uncertain) => {
                "request accounting publication is uncertain; inspect before retrying"
            }
            Self::History(_) => "request accounting storage could not be verified",
            Self::Session(SessionLeaseError::PublicationUncertain(_)) => {
                "session publication is visible but durable storage is uncertain"
            }
            Self::Session(SessionLeaseError::AlreadyExists { .. }) => {
                "session snapshot already exists; it was not replaced"
            }
            Self::Session(_) => "leased session storage could not be verified",
            Self::InvalidState(message) | Self::SpendRefused(message) => message,
        };
        for c in message.chars().filter(|c| !c.is_control()).take(512) {
            write!(f, "{c}")?;
        }
        Ok(())
    }
}
impl std::error::Error for AccountingError {}
impl From<HistoryError> for AccountingError {
    fn from(error: HistoryError) -> Self {
        Self::History(error)
    }
}
impl From<SessionLeaseError> for AccountingError {
    fn from(error: SessionLeaseError) -> Self {
        Self::Session(error)
    }
}
impl AccountingError {
    pub fn is_publication_uncertain(&self) -> bool {
        matches!(
            self,
            Self::History(HistoryError::Uncertain)
                | Self::Session(SessionLeaseError::PublicationUncertain(_))
        )
    }
}

pub(crate) fn validate_root_watermark(
    watermark: &SessionAccountingWatermark,
    owner: &str,
) -> Result<(), &'static str> {
    if watermark.owner_session_id != owner || watermark.child_id.is_some() {
        return Err("session accounting watermark has a different namespace");
    }
    watermark
        .known_ordinary_microcents
        .checked_add(watermark.known_housekeeping_microcents)
        .ok_or("session accounting watermark price sum overflows")?;
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Projection {
    revision: u64,
    input: u64,
    output: u64,
    priced: KnownPricedSubtotals,
    status: FullCostStatus,
}
impl Projection {
    fn from_checkpoint(checkpoint: &DetailedAccountingCheckpoint) -> Result<Self, AccountingError> {
        checkpoint.validate()?;
        let priced = checkpoint
            .known_priced_subtotals()
            .ok_or(AccountingError::InvalidState(
                "known priced accounting is unavailable; explicit recovery is required",
            ))?;
        priced
            .ordinary_microcents
            .checked_add(priced.housekeeping_microcents)
            .ok_or(AccountingError::InvalidState(
                "known priced accounting sum overflows",
            ))?;
        Ok(Self {
            revision: checkpoint.revision().0,
            input: checkpoint
                .totals()
                .ordinary
                .input_tokens
                .checked_add(checkpoint.totals().housekeeping.input_tokens)
                .ok_or(AccountingError::InvalidState(
                    "known input accounting sum overflows",
                ))?,
            output: checkpoint
                .totals()
                .ordinary
                .output_tokens
                .checked_add(checkpoint.totals().housekeeping.output_tokens)
                .ok_or(AccountingError::InvalidState(
                    "known output accounting sum overflows",
                ))?,
            priced,
            status: match checkpoint.totals().knownness {
                _ if checkpoint.pending().is_some() => FullCostStatus::Uncertain,
                AccountingKnownness::Uncertain => FullCostStatus::Uncertain,
                AccountingKnownness::UnknownLegacy => FullCostStatus::UnknownLegacy,
                AccountingKnownness::UnknownUsage => FullCostStatus::UnknownUsage,
                AccountingKnownness::Known
                    if checkpoint.totals().ordinary.cost_microcents.is_none()
                        || checkpoint.totals().housekeeping.cost_microcents.is_none() =>
                {
                    FullCostStatus::Unpriced
                }
                AccountingKnownness::Known => FullCostStatus::Known,
            },
        })
    }
    fn from_watermark(value: &SessionAccountingWatermark) -> Self {
        Self {
            revision: value.revision,
            input: value.known_input_tokens,
            output: value.known_output_tokens,
            priced: KnownPricedSubtotals {
                ordinary_microcents: value.known_ordinary_microcents,
                housekeeping_microcents: value.known_housekeeping_microcents,
            },
            status: value.full_cost_status,
        }
    }
    fn follows(self, previous: Self) -> Result<(), AccountingError> {
        if self.revision < previous.revision
            || self.input < previous.input
            || self.output < previous.output
            || self.priced.ordinary_microcents < previous.priced.ordinary_microcents
            || self.priced.housekeeping_microcents < previous.priced.housekeeping_microcents
            || (self.revision == previous.revision && self != previous)
        {
            return Err(AccountingError::InvalidState(
                "accounting checkpoint is behind or inconsistent with its anchor",
            ));
        }
        Ok(())
    }
    fn cost(self) -> Result<u64, AccountingError> {
        self.priced
            .ordinary_microcents
            .checked_add(self.priced.housekeeping_microcents)
            .ok_or(AccountingError::InvalidState(
                "known priced accounting sum overflows",
            ))
    }
}

pub struct NamespaceAccounting {
    home: PathBuf,
    owner: String,
    child: Option<String>,
    baseline: AccountingBaseline,
    journal: Arc<dyn CompactionJournal>,
    floor: Mutex<Projection>,
}
impl std::fmt::Debug for NamespaceAccounting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NamespaceAccounting")
    }
}
impl NamespaceAccounting {
    fn new(
        home: &Path,
        owner: &str,
        child: Option<&str>,
        journal: Arc<dyn CompactionJournal>,
        checkpoint: &DetailedAccountingCheckpoint,
    ) -> Result<Self, AccountingError> {
        if checkpoint.owner_session_id() != owner || checkpoint.child_id() != child {
            return Err(AccountingError::InvalidState(
                "accounting namespace does not match its held lease",
            ));
        }
        if checkpoint.pending().is_some()
            || checkpoint.totals().knownness == AccountingKnownness::Uncertain
        {
            return Err(AccountingError::InvalidState(
                "a pending uncertain request requires explicit inspection before admission",
            ));
        }
        Ok(Self {
            home: home.into(),
            owner: owner.into(),
            child: child.map(str::to_owned),
            baseline: checkpoint.baseline(),
            journal,
            floor: Mutex::new(Projection::from_checkpoint(checkpoint)?),
        })
    }

    fn accept_checkpoint(
        &self,
        checkpoint: &DetailedAccountingCheckpoint,
    ) -> Result<(), AccountingError> {
        if checkpoint.owner_session_id() != self.owner
            || checkpoint.child_id() != self.child.as_deref()
            || checkpoint.baseline() != self.baseline
        {
            return Err(AccountingError::InvalidState(
                "accounting checkpoint changed namespace",
            ));
        }
        let next = Projection::from_checkpoint(checkpoint)?;
        let mut floor = self.floor.lock().map_err(|_| {
            AccountingError::InvalidState("accounting projection state is unavailable")
        })?;
        next.follows(*floor)?;
        *floor = next;
        Ok(())
    }

    /// Legacy-only projection. A selected retry binding or refusal remains an
    /// explicit unsupported projection before any options or journal mutation.
    pub fn checkpoint(&self) -> Result<AccountingCheckpoint, AccountingError> {
        let checkpoint = self.journal.accounting_checkpoint()?;
        let detailed = DetailedAccountingCheckpoint::from_legacy(checkpoint.clone())?;
        self.accept_checkpoint(&detailed)?;
        Ok(checkpoint)
    }

    pub fn checkpoint_detailed(&self) -> Result<DetailedAccountingCheckpoint, AccountingError> {
        let checkpoint = self.journal.accounting_checkpoint_detailed()?;
        self.accept_checkpoint(&checkpoint)?;
        Ok(checkpoint)
    }

    pub fn apply_options(
        &self,
        options: &mut TurnOptions,
        policy: Option<NamespaceSpendPolicy>,
    ) -> Result<(), AccountingError> {
        self.validate_turn(options)?;
        let checkpoint = DetailedAccountingCheckpoint::from_legacy(self.checkpoint()?)?;
        self.apply_checkpoint(options, policy, &checkpoint)
    }

    /// A current invocation's policy is an admission input only. Retained
    /// refusal records never select or authorize retries for another prompt.
    pub fn apply_options_detailed(
        &self,
        options: &mut TurnOptions,
        policy: Option<NamespaceSpendPolicy>,
        retry_policy: Option<&RetryPolicyBinding>,
    ) -> Result<(), AccountingError> {
        self.validate_turn(options)?;
        if retry_policy.is_some() && (policy.is_some() || options.spend_allowance.is_some()) {
            return Err(AccountingError::SpendRefused(
                "final-rejection retry requires an uncapped invocation",
            ));
        }
        let checkpoint = self.checkpoint_detailed()?;
        self.apply_checkpoint(options, policy, &checkpoint)
    }

    fn validate_turn(&self, options: &TurnOptions) -> Result<(), AccountingError> {
        if options.session_id != self.child.as_ref().unwrap_or(&self.owner).as_str() {
            return Err(AccountingError::InvalidState(
                "turn session differs from the accounting namespace",
            ));
        }
        Ok(())
    }

    fn apply_checkpoint(
        &self,
        options: &mut TurnOptions,
        policy: Option<NamespaceSpendPolicy>,
        checkpoint: &DetailedAccountingCheckpoint,
    ) -> Result<(), AccountingError> {
        if checkpoint.pending().is_some()
            || checkpoint.totals().knownness == AccountingKnownness::Uncertain
        {
            return Err(AccountingError::InvalidState(
                "a pending uncertain request requires explicit inspection before admission",
            ));
        }
        let inherited = options.spend_allowance;
        let permission = match (policy, inherited) {
            (Some(namespace), Some(turn)) => {
                namespace.allow_unpriced_housekeeping && turn.allow_unpriced_housekeeping
            }
            (Some(namespace), None) => namespace.allow_unpriced_housekeeping,
            (None, Some(turn)) => turn.allow_unpriced_housekeeping,
            (None, None) => false,
        };
        if (policy.is_some() || inherited.is_some())
            && (checkpoint.baseline() == AccountingBaseline::UnknownLegacy
                || checkpoint.totals().knownness != AccountingKnownness::Known
                || checkpoint.totals().ordinary.cost_microcents.is_none()
                || (checkpoint.totals().housekeeping.cost_microcents.is_none() && !permission))
        {
            return Err(AccountingError::SpendRefused(
                "spend policy cannot use unknown historical usage or unpriced ordinary work",
            ));
        }
        let namespace = policy
            .map(|policy| -> Result<SpendAllowance, AccountingError> {
                let spent = Projection::from_checkpoint(checkpoint)?.cost()?;
                Ok(SpendAllowance {
                    remaining_microcents: policy.maximum_microcents.checked_sub(spent).ok_or(
                        AccountingError::SpendRefused("namespace spend allowance is exhausted"),
                    )?,
                    allow_unpriced_housekeeping: policy.allow_unpriced_housekeeping,
                })
            })
            .transpose()?;
        let allowance = match (namespace, inherited) {
            (Some(namespace), Some(turn)) => Some(SpendAllowance {
                remaining_microcents: namespace
                    .remaining_microcents
                    .min(turn.remaining_microcents),
                allow_unpriced_housekeeping: permission,
            }),
            (Some(namespace), None) => Some(namespace),
            (None, Some(turn)) => Some(turn),
            (None, None) => None,
        };
        // Every validation and arithmetic operation completes before assignment.
        options.journal = Some(Arc::clone(&self.journal));
        options.spend_allowance = allowance;
        Ok(())
    }
}

#[derive(Clone, Copy, Default)]
struct Prefix {
    input: u64,
    output: u64,
    cost: u64,
}

pub struct RootSessionAccounting {
    namespace: NamespaceAccounting,
    prefix: Prefix,
}
impl std::fmt::Debug for RootSessionAccounting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RootSessionAccounting")
    }
}
impl RootSessionAccounting {
    pub fn namespace(&self) -> &NamespaceAccounting {
        &self.namespace
    }

    pub fn reconcile(&self, snapshot: &mut SessionFile) -> Result<AccountingView, AccountingError> {
        validate_snapshot_identity(snapshot, &self.namespace.owner)?;
        let checkpoint = self.namespace.checkpoint_detailed()?;
        let projection = Projection::from_checkpoint(&checkpoint)?;
        if let Some(watermark) = &snapshot.accounting_watermark {
            validate_root_watermark(watermark, &self.namespace.owner)
                .map_err(AccountingError::InvalidState)?;
            projection.follows(Projection::from_watermark(watermark))?;
        }
        let view = AccountingView {
            revision: projection.revision,
            input_tokens: self.prefix.input.checked_add(projection.input).ok_or(
                AccountingError::InvalidState("projected input accounting overflows"),
            )?,
            output_tokens: self.prefix.output.checked_add(projection.output).ok_or(
                AccountingError::InvalidState("projected output accounting overflows"),
            )?,
            known_cost_microcents: self.prefix.cost.checked_add(projection.cost()?).ok_or(
                AccountingError::InvalidState("projected known price accounting overflows"),
            )?,
            full_cost_status: projection.status,
        };
        snapshot.input_tokens = view.input_tokens;
        snapshot.output_tokens = view.output_tokens;
        snapshot.cost_microcents = view.known_cost_microcents;
        snapshot.accounting_watermark = Some(SessionAccountingWatermark {
            owner_session_id: self.namespace.owner.clone(),
            child_id: None,
            revision: projection.revision,
            known_input_tokens: projection.input,
            known_output_tokens: projection.output,
            known_ordinary_microcents: projection.priced.ordinary_microcents,
            known_housekeeping_microcents: projection.priced.housekeeping_microcents,
            full_cost_status: projection.status,
        });
        Ok(view)
    }

    pub fn persist(
        &self,
        lease: &SessionLease,
        snapshot: &mut SessionFile,
    ) -> Result<AccountingView, AccountingError> {
        if lease.session_id() != self.namespace.owner || lease.home() != self.namespace.home {
            return Err(AccountingError::InvalidState(
                "snapshot persistence requires the original held session lease",
            ));
        }
        let view = self.reconcile(snapshot)?;
        lease.save(snapshot)?;
        Ok(view)
    }
}

fn validate_snapshot_identity(snapshot: &SessionFile, owner: &str) -> Result<(), AccountingError> {
    if snapshot.session_id != owner || snapshot.schema != "orbit.session/v1" {
        return Err(AccountingError::InvalidState(
            "saved session identity or schema does not match its lease",
        ));
    }
    Ok(())
}

fn prefix_from_saved(
    saved: &SessionFile,
    checkpoint: &DetailedAccountingCheckpoint,
) -> Result<Prefix, AccountingError> {
    let current = Projection::from_checkpoint(checkpoint)?;
    if let Some(watermark) = &saved.accounting_watermark {
        validate_root_watermark(watermark, checkpoint.owner_session_id())
            .map_err(AccountingError::InvalidState)?;
        let previous = Projection::from_watermark(watermark);
        current.follows(previous)?;
        let prefix = Prefix {
            input: saved.input_tokens.checked_sub(previous.input).ok_or(
                AccountingError::InvalidState("saved input is below its accounting anchor"),
            )?,
            output: saved.output_tokens.checked_sub(previous.output).ok_or(
                AccountingError::InvalidState("saved output is below its accounting anchor"),
            )?,
            cost: saved.cost_microcents.checked_sub(previous.cost()?).ok_or(
                AccountingError::InvalidState("saved known price is below its accounting anchor"),
            )?,
        };
        if checkpoint.baseline() == AccountingBaseline::FreshKnownZero
            && (prefix.input != 0 || prefix.output != 0 || prefix.cost != 0)
        {
            return Err(AccountingError::InvalidState(
                "fresh accounting has an inconsistent inherited prefix",
            ));
        }
        Ok(prefix)
    } else if checkpoint.baseline() == AccountingBaseline::FreshKnownZero {
        Ok(Prefix::default())
    } else if current.revision == 0
        && current.input == 0
        && current.output == 0
        && current.priced == KnownPricedSubtotals::known_zero()
        && checkpoint.pending().is_none()
        && checkpoint.last_settlement().is_none()
    {
        Ok(Prefix {
            input: saved.input_tokens,
            output: saved.output_tokens,
            cost: saved.cost_microcents,
        })
    } else {
        Err(AccountingError::InvalidState(
            "legacy accounting has work but no saved migration anchor",
        ))
    }
}

/// Callers retain this exact session lease throughout engine work and persistence.
pub fn prepare_root(
    lease: &SessionLease,
    snapshot: &mut SessionFile,
    origin: RootOrigin,
) -> Result<RootSessionAccounting, AccountingError> {
    validate_snapshot_identity(snapshot, lease.session_id())?;
    let saved = lease.load_optional()?;
    if origin == RootOrigin::FreshCandidate
        && (saved.is_some()
            || snapshot.accounting_watermark.is_some()
            || snapshot.turns != 0
            || snapshot.input_tokens != 0
            || snapshot.output_tokens != 0
            || snapshot.cost_microcents != 0)
    {
        return Err(AccountingError::InvalidState(
            "fresh session candidate collides with saved or inherited state",
        ));
    }
    let journal = crate::context_history::context_journal(lease.home(), lease.session_id(), None)?;
    let checkpoint = match journal.accounting_checkpoint_detailed() {
        Ok(_) if saved.is_none() => {
            return Err(AccountingError::InvalidState(
                "accounting exists without its snapshot; explicit recovery is required",
            ));
        }
        Ok(_) if origin == RootOrigin::ForkedThisInvocation => {
            return Err(AccountingError::InvalidState(
                "fork target accounting already exists",
            ));
        }
        Ok(value) => value,
        Err(HistoryError::Missing) => {
            if saved
                .as_ref()
                .is_some_and(|saved| saved.accounting_watermark.is_some())
            {
                return Err(AccountingError::InvalidState(
                    "saved accounting anchor exists but its journal is missing",
                ));
            }
            journal.initialize_accounting_detailed(if origin == RootOrigin::FreshCandidate {
                AccountingBaseline::FreshKnownZero
            } else {
                AccountingBaseline::UnknownLegacy
            })?
        }
        Err(error) => return Err(error.into()),
    };
    let namespace =
        NamespaceAccounting::new(lease.home(), lease.session_id(), None, journal, &checkpoint)?;
    if origin == RootOrigin::ForkedThisInvocation || saved.is_none() {
        // These are the explicit fork/absent-files bootstrap rules, never a
        // fallback for an inherited watermark in an existing saved session.
        snapshot.accounting_watermark = None;
    }
    let prefix = if let Some(saved) = &saved {
        prefix_from_saved(saved, &checkpoint)?
    } else if origin == RootOrigin::FreshCandidate {
        Prefix::default()
    } else {
        // Only the explicit absent-files legacy bootstrap may inherit candidate
        // numbers. Its foreign watermark is not used as evidence.
        Prefix {
            input: snapshot.input_tokens,
            output: snapshot.output_tokens,
            cost: snapshot.cost_microcents,
        }
    };
    let mut accounting = RootSessionAccounting { namespace, prefix };
    if saved.is_none() {
        accounting.reconcile(snapshot)?;
        lease.save_if_absent(snapshot)?;
        let persisted = lease.load()?;
        let final_checkpoint = accounting.namespace.checkpoint_detailed()?;
        if final_checkpoint.revision().0 != 0
            || final_checkpoint.pending().is_some()
            || persisted.accounting_watermark != snapshot.accounting_watermark
        {
            return Err(AccountingError::InvalidState(
                "initial accounting anchor changed before admission",
            ));
        }
        accounting.prefix = prefix_from_saved(&persisted, &final_checkpoint)?;
    } else {
        accounting.persist(lease, snapshot)?;
    }
    Ok(accounting)
}

/// The actual AgentRun and its originating store/home remain held by the caller.
pub fn prepare_child(
    home: &Path,
    run: &orbit_engine::agent_store::AgentRun,
    origin: ChildOrigin,
) -> Result<NamespaceAccounting, AccountingError> {
    let saved = run.snapshot();
    let journal = crate::context_history::context_journal(
        home,
        &saved.owner_session_id,
        Some(&saved.agent_id),
    )?;
    let checkpoint = match journal.accounting_checkpoint_detailed() {
        Ok(_) if origin == ChildOrigin::CreatedThisInvocation => {
            return Err(AccountingError::InvalidState(
                "new child accounting already exists",
            ));
        }
        Ok(value) => value,
        Err(HistoryError::Missing) => journal.initialize_accounting_detailed(
            if origin == ChildOrigin::CreatedThisInvocation {
                AccountingBaseline::FreshKnownZero
            } else {
                AccountingBaseline::UnknownLegacy
            },
        )?,
        Err(error) => return Err(error.into()),
    };
    NamespaceAccounting::new(
        home,
        &saved.owner_session_id,
        Some(&saved.agent_id),
        journal,
        &checkpoint,
    )
}
