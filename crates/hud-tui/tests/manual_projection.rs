use orbit_hud_tui::model::TranscriptLine;
use orbit_hud_tui::msg::{
    ContextProjection, CostQualification, ManualOutcome, ProjectionReason, SessionProjection,
};
use orbit_hud_tui::proto::panels::{FileChangeRow, TaskRow};
use orbit_hud_tui::proto::runtime::apply_session_projection;
use orbit_hud_tui::proto::scenario::{ActivityRow, Scenario, Tape};
use orbit_hud_tui::worker::{
    CancelHandle, ForegroundKind, ForegroundOperation, ManualAction, ManualOperation,
    SessionBinding, WorkerCommand,
};
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicUsize, Ordering},
};

fn binding() -> SessionBinding {
    SessionBinding {
        session_id: "projection-session".into(),
        generation: 1,
    }
}
fn lines() -> Vec<TranscriptLine> {
    vec![
        TranscriptLine::User {
            text: "preserved intent".into(),
            time: None,
        },
        TranscriptLine::Assistant {
            text: "preserved answer".into(),
            time: None,
        },
    ]
}
fn projection(reason: ProjectionReason, cost: CostQualification) -> SessionProjection {
    SessionProjection {
        binding: binding(),
        model: "selected-model".into(),
        provider: "selected-provider".into(),
        priced: false,
        lines: lines(),
        turns: 7,
        input_tokens: 111,
        output_tokens: 47,
        cost_microcents: 67,
        cost,
        context: ContextProjection::Unavailable,
        reason,
    }
}
fn initial() -> Scenario {
    let mut s = Scenario::new();
    assert!(apply_session_projection(
        projection(
            ProjectionReason::Initial,
            CostQualification::Known { revision: 2 }
        ),
        &mut s,
        10
    ));
    assert!(s.take_view_dirty());
    assert!(!s.take_view_dirty());
    s
}
fn counted(counter: &Arc<AtomicUsize>) -> CancelHandle {
    let counter = counter.clone();
    Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    })
}
fn terminal(
    operation: ManualOperation,
    outcome: ManualOutcome,
    applied: bool,
) -> SessionProjection {
    projection(
        ProjectionReason::Manual {
            operation,
            outcome,
            applied,
        },
        CostQualification::Known { revision: 4 },
    )
}

#[test]
fn early_cancel_is_latched_into_exact_token_and_closed_before_the_next_operation() {
    let first = ManualOperation::new(binding(), ManualAction::Compact, 1).unwrap();
    let old = Arc::new(AtomicUsize::new(0));
    let next = Arc::new(AtomicUsize::new(0));
    assert!(first.cancel().unwrap());
    let registration = first.install_cancel(counted(&old)).unwrap();
    assert_eq!(old.load(Ordering::SeqCst), 1);
    drop(registration);
    let second = ManualOperation::new(binding(), ManualAction::Compact, 2).unwrap();
    let next_registration = second.install_cancel(counted(&next)).unwrap();
    assert!(!first.cancel().unwrap());
    assert_eq!(old.load(Ordering::SeqCst), 1);
    assert_eq!(next.load(Ordering::SeqCst), 0);
    assert!(second.cancel().unwrap());
    assert_eq!(next.load(Ordering::SeqCst), 1);
    drop(next_registration);
}

#[test]
fn installation_and_cancellation_race_reaches_only_its_captured_callback() {
    for id in 1..=16 {
        let operation = ManualOperation::new(binding(), ManualAction::Compact, id).unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(2));
        let thread_operation = operation.clone();
        let thread_barrier = barrier.clone();
        let thread = std::thread::spawn(move || {
            thread_barrier.wait();
            assert!(thread_operation.cancel().unwrap());
        });
        barrier.wait();
        let registration = operation.install_cancel(counted(&count)).unwrap();
        thread.join().unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        drop(registration);
        assert!(!operation.cancel().unwrap());
    }
}

#[test]
fn operations_refuse_invalid_ids_reinstallation_and_install_after_unstarted_close() {
    assert!(ManualOperation::new(binding(), ManualAction::Compact, 0).is_err());
    let mut invalid = binding();
    invalid.generation = 0;
    assert!(ManualOperation::new(invalid, ManualAction::Compact, 1).is_err());
    let count = Arc::new(AtomicUsize::new(0));
    let closed = ManualOperation::new(binding(), ManualAction::Compact, 1).unwrap();
    closed.finish_unstarted().unwrap();
    assert!(closed.install_cancel(counted(&count)).is_err());
    assert!(!closed.cancel().unwrap());
    let live = ManualOperation::new(binding(), ManualAction::Compact, 2).unwrap();
    let registration = live.install_cancel(counted(&count)).unwrap();
    assert!(live.install_cancel(counted(&count)).is_err());
    assert!(live.finish_unstarted().is_err());
    drop(registration);
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn manual_admission_invalidates_full_bill_without_changing_prefix_or_revision_floor() {
    let mut s = initial();
    let operation = s.new_manual_operation(ManualAction::Compact).unwrap();
    assert!(s.admit_manual(operation.clone()));
    assert!(s.is_busy());
    assert_eq!(s.pending_manual(), Some(&operation));
    assert_eq!(s.cost_qualification(), CostQualification::Unavailable);
    assert_eq!(s.qualified_revision_floor(), Some(2));
    assert_eq!(
        (s.turns, s.input_tokens, s.output_tokens, s.cost_microcents),
        (7, 111, 47, 67)
    );
    assert!(s.take_view_dirty());
    assert!(!s.take_view_dirty());
    assert!(s.new_manual_operation(ManualAction::Clear).is_err());
}

#[test]
fn terminal_requires_arc_identity_and_preserves_pending_on_a_forged_matching_id() {
    let mut s = initial();
    let operation = s.new_manual_operation(ManualAction::Compact).unwrap();
    assert!(s.admit_manual(operation.clone()));
    s.take_view_dirty();
    let forged = ManualOperation::new(
        operation.source().clone(),
        operation.action(),
        operation.id(),
    )
    .unwrap();
    assert_ne!(forged, operation);
    assert!(!apply_session_projection(
        terminal(forged, ManualOutcome::Completed, true),
        &mut s,
        20
    ));
    assert!(s.is_busy());
    assert_eq!(s.pending_manual(), Some(&operation));
    assert_eq!(s.cost_qualification(), CostQualification::Unavailable);
    assert!(!s.take_view_dirty());
    assert_eq!(s.transcript[0].text, "preserved intent");
    assert!(apply_session_projection(
        terminal(operation, ManualOutcome::Failed, false),
        &mut s,
        21
    ));
    assert!(!s.is_busy());
    assert_eq!(s.turns, 7);
    assert!(s.take_view_dirty());
}

#[test]
fn stale_qualified_refresh_is_rejected_wholly_after_an_unavailable_projection() {
    let mut s = initial();
    let mut unavailable = projection(ProjectionReason::Refresh, CostQualification::Unavailable);
    unavailable.cost_microcents = 100;
    assert!(apply_session_projection(unavailable, &mut s, 20));
    s.take_view_dirty();
    let mut stale = projection(
        ProjectionReason::Refresh,
        CostQualification::Known { revision: 1 },
    );
    stale.lines = vec![TranscriptLine::System("obsolete replacement".into())];
    stale.cost_microcents = 1;
    assert!(!apply_session_projection(stale, &mut s, 21));
    assert_eq!(s.qualified_revision_floor(), Some(2));
    assert_eq!(s.cost_qualification(), CostQualification::Unavailable);
    assert_eq!(s.cost_microcents, 100);
    assert_eq!(s.transcript[0].text, "preserved intent");
    assert!(!s.take_view_dirty());
}

#[test]
fn previous_refresh_cannot_erase_new_prompt_or_release_a_manual_operation() {
    for manual in [false, true] {
        let mut s = initial();
        let operation = s.new_manual_operation(ManualAction::Compact).unwrap();
        if manual {
            assert!(s.admit_manual(operation.clone()));
        } else {
            s.turn_live = true;
            s.transcript[0].text = "current live intent".into();
            s.invalidate_cost_qualification();
        }
        s.take_view_dirty();
        let before = s.transcript.clone();
        let stale = projection(
            ProjectionReason::Refresh,
            CostQualification::Known { revision: 2 },
        );
        assert!(
            !apply_session_projection(stale, &mut s, 30),
            "late previous refresh must not mutate active work"
        );
        assert_eq!(s.transcript, before);
        assert_eq!(
            (s.turns, s.input_tokens, s.output_tokens, s.cost_microcents),
            (7, 111, 47, 67)
        );
        assert_eq!(s.cost_qualification(), CostQualification::Unavailable);
        assert!(s.is_busy());
        assert!(!s.take_view_dirty());
        if manual {
            assert_eq!(s.pending_manual(), Some(&operation));
        }
    }
}

#[test]
fn manual_completion_preserves_workspace_and_assigns_whole_totals_without_user_turn() {
    let mut s = initial();
    s.tasks.push(TaskRow {
        title: "keep task".into(),
        status: "pending".into(),
    });
    s.file_changes.push(FileChangeRow {
        path: "keep.txt".into(),
        added: 2,
        removed: 1,
        hunks: None,
    });
    s.tapes.push(Tape {
        call_id: "prior-tool".into(),
        lines: vec!["prior output".into()],
        dropped: 0,
    });
    s.activity.push(ActivityRow {
        time: "00:00".into(),
        kind: "status".into(),
        target: "prior work".into(),
        fact: "keep".into(),
        digest: None,
    });
    let before = (
        s.tasks.clone(),
        s.file_changes.clone(),
        s.tapes.clone(),
        s.activity.clone(),
    );
    let operation = s.new_manual_operation(ManualAction::Compact).unwrap();
    assert!(s.admit_manual(operation.clone()));
    s.take_view_dirty();
    let mut view = terminal(operation, ManualOutcome::Completed, true);
    view.lines = vec![
        TranscriptLine::User {
            text: "historical data".into(),
            time: None,
        },
        TranscriptLine::Assistant {
            text: "safe summary".into(),
            time: None,
        },
    ];
    view.input_tokens = 122;
    view.output_tokens = 54;
    view.cost_microcents = 74;
    assert!(apply_session_projection(view, &mut s, 40));
    assert_eq!(
        (s.turns, s.input_tokens, s.output_tokens, s.cost_microcents),
        (7, 122, 54, 74)
    );
    assert!(!s.is_busy());
    assert_eq!(
        (&s.tasks, &s.file_changes, &s.tapes, &s.activity),
        (&before.0, &before.1, &before.2, &before.3)
    );
    assert!(s.take_view_dirty());
}

#[test]
fn context_replacement_invalidates_sample_and_noop_preserves_only_unchanged_history() {
    let mut s = initial();
    s.used_tokens = 4000;
    s.window_tokens = 64000;
    s.ctx_from = 0.5;
    s.ctx_to = 0.75;
    s.ctx_ms = 5;
    s.usage_shown_ms = 6;
    s.compacting_from = Some(999);
    s.ctx_breakdown = Some(orbit_frontend_protocol::ContextBreakdown {
        system: 1,
        memory: 2,
        tools: 3,
        messages: 3994,
        compact_at: 50000,
        reserve: 73,
    });
    let mut refresh = projection(
        ProjectionReason::Refresh,
        CostQualification::Known { revision: 2 },
    );
    refresh.context = ContextProjection::PreserveUnchanged;
    assert!(!apply_session_projection(refresh, &mut s, 49));
    assert_eq!((s.used_tokens, s.window_tokens), (4000, 64000));
    assert!(!s.take_view_dirty());
    let operation = s.new_manual_operation(ManualAction::Compact).unwrap();
    assert!(s.admit_manual(operation.clone()));
    let mut invalid = terminal(operation.clone(), ManualOutcome::Completed, true);
    invalid.context = ContextProjection::PreserveUnchanged;
    s.take_view_dirty();
    assert!(!apply_session_projection(invalid, &mut s, 50));
    assert_eq!(s.used_tokens, 4000);
    assert!(!s.take_view_dirty());
    let mut noop = terminal(operation, ManualOutcome::Completed, false);
    noop.context = ContextProjection::PreserveUnchanged;
    assert!(apply_session_projection(noop, &mut s, 51));
    assert_eq!((s.used_tokens, s.window_tokens), (4000, 64000));
    assert!(s.ctx_breakdown.is_some());
    let next = s.new_manual_operation(ManualAction::Compact).unwrap();
    assert!(s.admit_manual(next.clone()));
    assert!(apply_session_projection(
        terminal(next, ManualOutcome::Completed, true),
        &mut s,
        52
    ));
    assert_eq!(
        (s.used_tokens, s.window_tokens, s.usage_shown_ms),
        (0, 0, 0)
    );
    assert!(s.ctx_breakdown.is_none());
    assert!(s.compacting_from.is_none());
    assert_eq!((s.ctx_from, s.ctx_to, s.ctx_ms), (0.0, 0.0, 0));
}

#[test]
fn committed_clear_resets_real_identity_once_and_failed_clear_keeps_source() {
    let mut s = initial();
    s.tasks.push(TaskRow {
        title: "old workspace".into(),
        status: "pending".into(),
    });
    let operation = s.new_manual_operation(ManualAction::Clear).unwrap();
    assert!(s.admit_manual(operation.clone()));
    let mut failed = terminal(operation, ManualOutcome::Failed, false);
    failed.cost = CostQualification::Known { revision: 2 };
    assert!(apply_session_projection(failed, &mut s, 60));
    assert_eq!(s.session_binding(), Some(&binding()));
    assert_eq!(s.tasks.len(), 1);
    let next = s.new_manual_operation(ManualAction::Clear).unwrap();
    assert!(s.admit_manual(next.clone()));
    let mut fresh = terminal(next, ManualOutcome::Completed, true);
    fresh.binding = SessionBinding {
        session_id: "new-projection-session".into(),
        generation: 2,
    };
    fresh.lines.clear();
    fresh.turns = 0;
    fresh.input_tokens = 0;
    fresh.output_tokens = 0;
    fresh.cost_microcents = 0;
    fresh.cost = CostQualification::Known { revision: 0 };
    assert!(apply_session_projection(fresh.clone(), &mut s, 61));
    assert!(s.transcript.is_empty() && s.tasks.is_empty());
    assert_eq!(s.qualified_revision_floor(), Some(0));
    s.take_view_dirty();
    assert!(!apply_session_projection(fresh, &mut s, 62));
    assert!(!s.take_view_dirty());
    assert_eq!(s.session_binding().unwrap().generation, 2);
}

#[test]
fn same_length_cost_only_update_and_noop_terminal_always_mark_view_dirty() {
    let mut s = initial();
    let count = s.transcript.len();
    let turns = s.turns;
    assert!(apply_session_projection(
        projection(
            ProjectionReason::Refresh,
            CostQualification::Unpriced { revision: 2 }
        ),
        &mut s,
        70
    ));
    assert_eq!((s.transcript.len(), s.turns), (count, turns));
    assert!(s.take_view_dirty());
    assert!(!s.take_view_dirty());
    assert!(s.cost_status_text().contains("unpriced"));
    let operation = s.new_manual_operation(ManualAction::Compact).unwrap();
    assert!(s.admit_manual(operation.clone()));
    assert!(s.take_view_dirty());
    assert!(apply_session_projection(
        terminal(operation, ManualOutcome::Completed, false),
        &mut s,
        71
    ));
    assert_eq!((s.transcript.len(), s.turns), (count, turns));
    assert!(s.take_view_dirty());
    assert!(!s.take_view_dirty());
}

#[test]
fn historical_price_is_visible_even_when_the_selected_model_is_unpriced() {
    let mut s = initial();
    assert!(!s.priced);
    assert_eq!(s.cost_status_text(), "$0.0001");
    for (cost, suffix) in [
        (
            CostQualification::UnknownHistory { revision: 2 },
            "earlier cost unknown",
        ),
        (
            CostQualification::UnknownUsage { revision: 2 },
            "usage incomplete",
        ),
        (CostQualification::Unpriced { revision: 2 }, "unpriced work"),
        (
            CostQualification::Uncertain { revision: 2 },
            "accounting uncertain",
        ),
        (CostQualification::Unavailable, "bill unavailable"),
    ] {
        assert!(apply_session_projection(
            projection(ProjectionReason::Refresh, cost),
            &mut s,
            80
        ));
        assert_eq!(s.cost_status_text(), format!("$0.0001 · {suffix}"));
    }
    let mut empty = projection(ProjectionReason::Refresh, CostQualification::Unavailable);
    empty.cost_microcents = 0;
    assert!(apply_session_projection(empty, &mut s, 81));
    assert_eq!(s.cost_status_text(), "$0.0000 · bill unavailable");
}

#[test]
fn manual_and_foreground_admission_require_actual_initial_binding() {
    let mut s = Scenario::new();
    assert!(s.new_manual_operation(ManualAction::Compact).is_err());
    for kind in [
        ForegroundKind::Prompt,
        ForegroundKind::PlanPrompt,
        ForegroundKind::Control,
        ForegroundKind::Resume,
    ] {
        assert!(s.new_foreground_operation(kind).is_err());
        assert!(!s.admit_foreground(ForegroundOperation::new(binding(), kind, 1).unwrap()));
    }
    assert!(!s.admit_manual(ManualOperation::new(binding(), ManualAction::Compact, 1).unwrap()));
    assert!(!s.is_busy());
    assert!(s.session_binding().is_none());
    assert!(!s.take_view_dirty());
    assert!(apply_session_projection(
        projection(
            ProjectionReason::Initial,
            CostQualification::Known { revision: 2 }
        ),
        &mut s,
        90
    ));
    assert!(s.new_foreground_operation(ForegroundKind::Prompt).is_ok());
}

#[test]
fn ordinary_lifecycle_end_keeps_admission_busy_until_its_exact_whole_view() {
    for (kind, lifecycle) in [
        (ForegroundKind::Prompt, "turn_ended"),
        (ForegroundKind::PlanPrompt, "turn_failed"),
    ] {
        let mut s = initial();
        let operation = s.new_foreground_operation(kind).unwrap();
        assert!(s.admit_foreground(operation.clone()));
        assert!(s.ordinary_pending());
        assert_eq!(s.cost_qualification(), CostQualification::Unavailable);
        assert_eq!(
            (s.turns, s.input_tokens, s.output_tokens, s.cost_microcents),
            (7, 111, 47, 67)
        );
        assert_eq!(s.qualified_revision_floor(), Some(2));
        assert!(s.take_view_dirty());
        // These are the public lifecycle reductions used by ResponseFinished
        // and BackendError; neither is the checked whole-session terminal.
        s.apply("round_started", 91);
        s.apply(lifecycle, 92);
        assert!(!s.turn_live);
        assert!(s.is_busy());
        assert!(s.ordinary_pending());
        assert_eq!(s.pending_foreground(), Some(&operation));
        assert!(s.new_manual_operation(ManualAction::Compact).is_err());
        assert!(s.new_foreground_operation(ForegroundKind::Control).is_err());
        assert!(!apply_session_projection(
            projection(
                ProjectionReason::Refresh,
                CostQualification::Known { revision: 4 }
            ),
            &mut s,
            93
        ));
        assert!(!s.take_view_dirty());
        let mut checked = projection(
            ProjectionReason::Operation {
                operation: operation.clone(),
            },
            CostQualification::Known { revision: 4 },
        );
        checked.turns = 8;
        checked.input_tokens = 122;
        checked.output_tokens = 54;
        checked.cost_microcents = 74;
        assert!(apply_session_projection(checked, &mut s, 94));
        assert!(!s.is_busy());
        assert!(!s.ordinary_pending());
        assert!(s.pending_foreground().is_none());
        assert_eq!(
            (s.turns, s.input_tokens, s.output_tokens, s.cost_microcents),
            (8, 122, 54, 74)
        );
        assert_eq!(
            s.cost_qualification(),
            CostQualification::Known { revision: 4 }
        );
        assert!(s.take_view_dirty());
        let manual = s.new_manual_operation(ManualAction::Compact).unwrap();
        assert!(manual.id() > operation.id());
        assert!(s.admit_manual(manual.clone()));
        let mut completed = terminal(manual, ManualOutcome::Completed, false);
        completed.turns = 8;
        assert!(apply_session_projection(completed, &mut s, 95));
        assert_eq!(s.turns, 8);
    }
}

#[test]
fn stale_or_forged_control_terminal_cannot_release_an_admitted_operation() {
    let mut s = initial();
    s.used_tokens = 345;
    s.window_tokens = 1000;
    let operation = s.new_foreground_operation(ForegroundKind::Control).unwrap();
    assert!(s.admit_foreground(operation.clone()));
    s.take_view_dirty();
    let forged =
        ForegroundOperation::new(operation.source().clone(), operation.kind(), operation.id())
            .unwrap();
    assert_ne!(forged, operation);
    for (ticket, cost) in [
        (forged, CostQualification::Known { revision: 2 }),
        (operation.clone(), CostQualification::Known { revision: 1 }),
    ] {
        let mut wrong = projection(ProjectionReason::Operation { operation: ticket }, cost);
        wrong.lines.clear();
        wrong.turns = 0;
        wrong.cost_microcents = 0;
        assert!(!apply_session_projection(wrong, &mut s, 100));
        assert_eq!(s.pending_foreground(), Some(&operation));
        assert!(s.is_busy());
        assert_eq!(
            (s.turns, s.cost_microcents, s.used_tokens, s.window_tokens),
            (7, 67, 345, 1000)
        );
        assert_eq!(s.transcript[0].text, "preserved intent");
        assert_eq!(s.cost_qualification(), CostQualification::Unavailable);
        assert!(!s.take_view_dirty());
    }
    let mut foreign = projection(
        ProjectionReason::Operation {
            operation: operation.clone(),
        },
        CostQualification::Known { revision: 2 },
    );
    foreign.binding = SessionBinding {
        session_id: "foreign-control-target".into(),
        generation: 2,
    };
    assert!(!apply_session_projection(foreign, &mut s, 100));
    assert_eq!(s.session_binding(), Some(&binding()));
    assert_eq!(s.pending_foreground(), Some(&operation));
    assert!(!s.take_view_dirty());
    let correct = projection(
        ProjectionReason::Operation {
            operation: operation.clone(),
        },
        CostQualification::Known { revision: 2 },
    );
    assert!(apply_session_projection(correct.clone(), &mut s, 101));
    assert!(!s.is_busy());
    assert!(s.take_view_dirty());
    let next = s.new_foreground_operation(ForegroundKind::Control).unwrap();
    assert!(s.admit_foreground(next.clone()));
    s.take_view_dirty();
    assert!(!apply_session_projection(correct, &mut s, 102));
    assert_eq!(s.pending_foreground(), Some(&next));
    assert!(!s.take_view_dirty());
}

#[test]
fn bound_resume_then_undo_publish_one_atomic_identity_and_current_manual_counters() {
    let mut s = initial();
    s.tasks.push(TaskRow {
        title: "old workspace".into(),
        status: "pending".into(),
    });
    let resume = s.new_foreground_operation(ForegroundKind::Resume).unwrap();
    assert!(s.admit_foreground(resume.clone()));
    assert!(s.new_manual_operation(ManualAction::Compact).is_err());
    let mut loaded = projection(
        ProjectionReason::Operation { operation: resume },
        CostQualification::Known { revision: 1 },
    );
    loaded.binding = SessionBinding {
        session_id: "resumed-session".into(),
        generation: 2,
    };
    loaded.turns = 15;
    loaded.input_tokens = 200;
    loaded.output_tokens = 90;
    loaded.cost_microcents = 123;
    loaded.lines = vec![
        TranscriptLine::User {
            text: "resumed source".into(),
            time: None,
        },
        TranscriptLine::Assistant {
            text: "resumed answer".into(),
            time: None,
        },
    ];
    assert!(apply_session_projection(loaded.clone(), &mut s, 110));
    assert!(s.tasks.is_empty());
    assert!(!s.is_busy());
    assert_eq!(s.session_binding(), Some(&loaded.binding));
    assert_eq!(s.qualified_revision_floor(), Some(1));
    assert_eq!(s.turns, 15);
    s.tasks.push(TaskRow {
        title: "new workspace".into(),
        status: "pending".into(),
    });
    let undo = s.new_foreground_operation(ForegroundKind::Control).unwrap();
    assert_eq!(undo.source(), &loaded.binding);
    assert!(s.admit_foreground(undo.clone()));
    s.take_view_dirty();
    assert!(!apply_session_projection(loaded.clone(), &mut s, 111));
    assert!(s.is_busy());
    assert!(s.new_manual_operation(ManualAction::Compact).is_err());
    assert!(!s.take_view_dirty());
    let mut undone = loaded;
    undone.reason = ProjectionReason::Operation { operation: undo };
    undone.turns = 14;
    undone.lines.clear();
    assert!(apply_session_projection(undone.clone(), &mut s, 112));
    assert_eq!(s.turns, 14);
    assert!(s.transcript.is_empty());
    assert_eq!(s.tasks.len(), 1);
    assert!(!s.is_busy());
    let compact = s.new_manual_operation(ManualAction::Compact).unwrap();
    assert_eq!(compact.source(), &undone.binding);
    assert!(s.admit_manual(compact.clone()));
    undone.reason = ProjectionReason::Manual {
        operation: compact,
        outcome: ManualOutcome::Completed,
        applied: false,
    };
    assert!(apply_session_projection(undone, &mut s, 113));
    assert_eq!(s.turns, 14);
    assert!(!s.is_busy());
}

#[test]
fn foreground_ticket_consumption_validates_command_kind_and_exact_once_start() {
    let operation = ForegroundOperation::new(binding(), ForegroundKind::Prompt, 1).unwrap();
    assert!(operation.start(&WorkerCommand::Undo).is_err());
    let prompt = WorkerCommand::Prompt("unchanged user prompt".into());
    let registration = operation.start(&prompt).unwrap();
    assert!(operation.start(&prompt).is_err());
    assert!(operation.finish_unstarted().is_err());
    drop(registration);
    assert!(operation.start(&prompt).is_err());
    let closed = ForegroundOperation::new(binding(), ForegroundKind::Control, 2).unwrap();
    closed.finish_unstarted().unwrap();
    assert!(closed.start(&WorkerCommand::Undo).is_err());
    assert!(ForegroundOperation::new(binding(), ForegroundKind::Prompt, 0).is_err());
    assert_eq!(
        prompt,
        WorkerCommand::Prompt("unchanged user prompt".into())
    );
    assert_eq!(
        WorkerCommand::PlanPrompt("unchanged plan prompt".into()).foreground_kind(),
        Some(ForegroundKind::PlanPrompt)
    );
}
