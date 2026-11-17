//! Scheduled prompts: cron-style and one-shot jobs that survive a restart.
//!
//! Jobs live in `$ORBIT_HOME/schedules.json`. The model's `CronCreate`,
//! `CronList`, `CronDelete` and `ScheduleWakeup` tools edit that file; an
//! open terminal session fires a job's prompt when it is due, the session
//! is idle, and the job belongs to the session's working directory. Nothing
//! fires while ORBIT is closed: a recurring job that was missed by more
//! than ten minutes waits for its next time, a missed one-shot fires once,
//! late. A recurring job expires seven days after it was created unless it
//! was made `durable`.

use chrono::{Datelike, Local, TimeZone, Timelike};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const MAX_JOBS: usize = 32;
pub const MAX_PROMPT_CHARS: usize = 4_000;
const MAX_FILE_BYTES: u64 = 512 * 1024;
const EXPIRY_SECS: u64 = 7 * 24 * 3600;
/// A recurring fire later than this is skipped, not delivered late.
const LATE_SECS: u64 = 10 * 60;
const LOCK_BUSY: &str =
    "schedules lock is busy; retry after the other scheduler operation finishes";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    /// The working directory whose sessions run this job.
    pub cwd: String,
    pub prompt: String,
    /// Five fields, local time: minute hour day-of-month month day-of-week.
    #[serde(default)]
    pub cron: Option<String>,
    /// One-shot: fire at this unix time, then remove the job.
    #[serde(default)]
    pub at: Option<u64>,
    pub created: u64,
    /// The scheduled time most recently handled (fired or skipped).
    #[serde(default)]
    pub last: Option<u64>,
    #[serde(default)]
    pub durable: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    #[serde(default)]
    jobs: Vec<Job>,
}

pub fn path(home: &Path) -> PathBuf {
    home.join("schedules.json")
}

/// A best-effort listing for read-only displays. Mutators and claimers use
/// `load_checked` so an invalid file cannot be mistaken for an empty queue.
pub fn load(home: &Path) -> Vec<Job> {
    load_checked(home).unwrap_or_default()
}

fn queue_metadata(home: &Path) -> Result<Option<std::fs::Metadata>, String> {
    match std::fs::symlink_metadata(path(home)) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("schedules could not be inspected: {error}")),
    }
}

fn validate_queue_metadata(metadata: &std::fs::Metadata) -> Result<(), String> {
    if !metadata.is_file() {
        return Err("schedules must be a regular file".into());
    }
    if metadata.len() > MAX_FILE_BYTES {
        return Err(format!("schedules exceed the {MAX_FILE_BYTES}-byte limit"));
    }
    Ok(())
}

/// Read a bounded regular queue file. Only a missing file is an empty queue;
/// a damaged or inaccessible queue must be inspected before it is changed.
pub fn load_checked(home: &Path) -> Result<Vec<Job>, String> {
    use std::io::Read;
    let Some(metadata) = queue_metadata(home)? else {
        return Ok(Vec::new());
    };
    validate_queue_metadata(&metadata)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    let file = match options.open(path(home)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("schedules could not be opened: {error}")),
    };
    validate_queue_metadata(
        &file
            .metadata()
            .map_err(|error| format!("schedules could not be inspected: {error}"))?,
    )?;
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("schedules could not be read: {error}"))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(format!("schedules exceed the {MAX_FILE_BYTES}-byte limit"));
    }
    serde_json::from_slice::<File>(&bytes)
        .map(|file| file.jobs)
        .map_err(|error| {
            // A serde type error can quote the malformed value. Do not echo
            // prompt text or other file contents into an operator diagnostic.
            format!(
                "schedules contain invalid job data at line {}, column {}",
                error.line(),
                error.column()
            )
        })
}

pub fn save(home: &Path, jobs: &[Job]) -> Result<(), String> {
    let path = path(home);
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(&File {
        jobs: jobs.to_vec(),
    })
    .map_err(|error| format!("schedules: {error}"))?;
    std::fs::write(&temp, bytes).map_err(|error| format!("schedules: {error}"))?;
    std::fs::rename(&temp, &path).map_err(|error| format!("schedules: {error}"))
}

// ───────────────────────────── cron ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cron {
    minutes: Vec<bool>,
    hours: Vec<bool>,
    days: Vec<bool>,
    months: Vec<bool>,
    weekdays: Vec<bool>,
    /// Both day fields restricted: either may match (the cron rule).
    day_or: bool,
}

fn field(text: &str, low: u32, high: u32) -> Option<Vec<bool>> {
    let mut set = vec![false; high as usize + 1];
    for part in text.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((range, step)) => (range, step.parse::<u32>().ok().filter(|s| *s > 0)?),
            None => (part, 1),
        };
        let (from, to) = if range == "*" {
            (low, high)
        } else if let Some((from, to)) = range.split_once('-') {
            (from.parse().ok()?, to.parse().ok()?)
        } else {
            let value: u32 = range.parse().ok()?;
            // `5/15` means "from 5, every 15".
            (value, if part.contains('/') { high } else { value })
        };
        if from < low || to > high || from > to {
            return None;
        }
        let mut value = from;
        while value <= to {
            set[value as usize] = true;
            value += step;
        }
    }
    Some(set)
}

impl Cron {
    pub fn parse(text: &str) -> Result<Self, String> {
        let fields: Vec<&str> = text.split_whitespace().collect();
        let [minute, hour, day, month, weekday] = fields.as_slice() else {
            return Err(
                "a cron expression has five fields: minute hour day-of-month month day-of-week"
                    .into(),
            );
        };
        let bad = |name: &str| format!("cron {name} field is not valid");
        let mut weekdays = field(weekday, 0, 7).ok_or_else(|| bad("day-of-week"))?;
        // 7 is Sunday too.
        if weekdays[7] {
            weekdays[0] = true;
        }
        weekdays.truncate(7);
        Ok(Self {
            minutes: field(minute, 0, 59).ok_or_else(|| bad("minute"))?,
            hours: field(hour, 0, 23).ok_or_else(|| bad("hour"))?,
            days: field(day, 1, 31).ok_or_else(|| bad("day-of-month"))?,
            months: field(month, 1, 12).ok_or_else(|| bad("month"))?,
            weekdays,
            day_or: *day != "*" && *weekday != "*",
        })
    }

    fn matches<T: Datelike + Timelike>(&self, time: &T) -> bool {
        let day = self.days[time.day() as usize];
        let weekday = self.weekdays[time.weekday().num_days_from_sunday() as usize];
        self.minutes[time.minute() as usize]
            && self.hours[time.hour() as usize]
            && self.months[time.month() as usize]
            && if self.day_or {
                day || weekday
            } else {
                day && weekday
            }
    }

    /// The first matching minute strictly after `after` (unix seconds),
    /// in local time; `None` when there is none within a year.
    pub fn next_after(&self, after: u64) -> Option<u64> {
        let mut minute = (after / 60 + 1) * 60;
        let limit = after + 366 * 24 * 3600;
        while minute <= limit {
            let time = Local.timestamp_opt(minute as i64, 0).single()?;
            if self.matches(&time) {
                return Some(minute);
            }
            // Skip whole hours and days that cannot match.
            minute += if !self.months[time.month() as usize] {
                24 * 3600 - (time.hour() * 3600 + time.minute() * 60) as u64
            } else if !self.hours[time.hour() as usize] {
                3600 - time.minute() as u64 * 60
            } else {
                60
            };
        }
        None
    }
}

// ───────────────────────────── firing ─────────────────────────────

/// When this job should next run, given what it has already handled.
fn next_time(job: &Job) -> Option<u64> {
    match (&job.cron, job.at) {
        (_, Some(at)) => job.last.is_none().then_some(at),
        (Some(cron), None) => Cron::parse(cron)
            .ok()?
            .next_after(job.last.unwrap_or(job.created)),
        (None, None) => None,
    }
}

fn expired(job: &Job, now: u64) -> bool {
    job.cron.is_some() && !job.durable && now > job.created.saturating_add(EXPIRY_SECS)
}

/// The prompts due now for `cwd`, with the job list as it stands after
/// handling them. `changed` says whether the list needs saving.
pub fn take_due(jobs: Vec<Job>, cwd: &str, now: u64) -> (Vec<String>, Vec<Job>, bool) {
    let mut prompts = Vec::new();
    let mut kept = Vec::new();
    let mut changed = false;
    for mut job in jobs {
        if expired(&job, now) {
            changed = true;
            continue;
        }
        if job.cwd != cwd {
            kept.push(job);
            continue;
        }
        match next_time(&job) {
            Some(when) if when <= now => {
                changed = true;
                let one_shot = job.at.is_some();
                if one_shot || now - when <= LATE_SECS {
                    prompts.push(job.prompt.clone());
                }
                if one_shot {
                    continue;
                }
                // Recurring: everything up to now is handled.
                job.last = Some(now);
                kept.push(job);
            }
            // A one-shot already handled, or a cron that can never match.
            None => changed = true,
            Some(_) => kept.push(job),
        }
    }
    (prompts, kept, changed)
}

/// Run `work` while holding the schedule file's lock, so two sessions (or a
/// session and a tool call) never read, decide and write at the same time.
/// The lock is an advisory `flock` on `schedules.lock`, held only for the
/// call. Failure to open or acquire the lock never runs `work`; a busy
/// lock returns immediately so polling cannot stall the terminal.
pub fn locked<T>(home: &Path, work: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    locked_with(
        home,
        |file| {
            rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
                |error| {
                    if error == rustix::io::Errno::WOULDBLOCK {
                        LOCK_BUSY.into()
                    } else {
                        format!("schedules lock could not be acquired: {error}")
                    }
                },
            )
        },
        work,
    )
}

fn locked_with<T>(
    home: &Path,
    acquire: impl FnOnce(&std::fs::File) -> Result<(), String>,
    work: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A lock must be an ordinary file, not a link or
        // a special file whose open could block before the lock is acquired.
        options.mode(0o600).custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    let file = options
        .open(home.join("schedules.lock"))
        .map_err(|error| format!("schedules lock could not be opened: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("schedules lock could not be inspected: {error}"))?;
    if !metadata.is_file() {
        return Err("schedules lock is not a regular file".into());
    }
    acquire(&file)?;
    let result = work();
    // Closing the descriptor releases the lock.
    drop(file);
    result
}

/// Load, take what is due for `cwd`, and save if anything changed. A job
/// fires in exactly one session: the whole step runs under the file lock,
/// and a fire that could not be recorded is not delivered.
pub fn fire_due(home: &Path, cwd: &str, now: u64) -> Result<Vec<String>, String> {
    if queue_metadata(home)?.is_none() {
        return Ok(Vec::new());
    }
    locked(home, || {
        let jobs = load_checked(home)?;
        if jobs.is_empty() {
            return Ok(Vec::new());
        }
        let (prompts, kept, changed) = take_due(jobs, cwd, now);
        if changed {
            // Not recorded as handled: firing now would repeat on every poll.
            save(home, &kept)?;
        }
        Ok(prompts)
    })
}

/// A one-line description for listings.
pub fn describe(job: &Job, now: u64) -> String {
    let when = match (next_time(job), &job.cron) {
        (Some(next), _) => {
            let secs = next.saturating_sub(now);
            if secs < 3600 {
                format!("next in {} min", secs.div_ceil(60))
            } else if secs < 48 * 3600 {
                format!("next in {} h", secs / 3600)
            } else {
                format!("next in {} d", secs / 86_400)
            }
        }
        (None, _) => "no further runs".to_owned(),
    };
    let kind = match (&job.cron, job.durable) {
        (Some(cron), true) => format!("cron `{cron}` (durable)"),
        (Some(cron), false) => format!("cron `{cron}`"),
        (None, _) => "once".to_owned(),
    };
    let prompt: String = job.prompt.chars().take(80).collect();
    format!("{} · {kind} · {when} · {prompt}", job.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> u64 {
        Local
            .with_ymd_and_hms(y, mo, d, h, mi, 0)
            .single()
            .unwrap()
            .timestamp() as u64
    }

    fn job(id: &str, cron: Option<&str>, at: Option<u64>, created: u64) -> Job {
        Job {
            id: id.into(),
            cwd: "/work".into(),
            prompt: format!("run {id}"),
            cron: cron.map(str::to_owned),
            at,
            created,
            last: None,
            durable: false,
        }
    }

    #[test]
    fn cron_fields_parse_and_reject() {
        assert!(Cron::parse("*/5 * * * *").is_ok());
        assert!(Cron::parse("0 9-17 * * 1-5").is_ok());
        assert!(Cron::parse("15,45 0 1 1,7 7").is_ok());
        for bad in [
            "",
            "* * * *",
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * * 13 *",
            "*/0 * * * *",
            "a * * * *",
            "5-1 * * * *",
            "* * * * * *",
        ] {
            assert!(Cron::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn next_after_finds_the_following_local_minute() {
        // 2026-03-10 is a Tuesday.
        let base = local(2026, 3, 10, 10, 2);
        let every5 = Cron::parse("*/5 * * * *").unwrap();
        assert_eq!(every5.next_after(base), Some(local(2026, 3, 10, 10, 5)));
        assert_eq!(
            every5.next_after(local(2026, 3, 10, 10, 5)),
            Some(local(2026, 3, 10, 10, 10))
        );
        let nine = Cron::parse("0 9 * * *").unwrap();
        assert_eq!(nine.next_after(base), Some(local(2026, 3, 11, 9, 0)));
        let weekdays = Cron::parse("30 8 * * 1-5").unwrap();
        // From Friday evening to Monday morning.
        assert_eq!(
            weekdays.next_after(local(2026, 3, 13, 20, 0)),
            Some(local(2026, 3, 16, 8, 30))
        );
        let sunday = Cron::parse("0 0 * * 7").unwrap();
        assert_eq!(sunday.next_after(base), Some(local(2026, 3, 15, 0, 0)));
        // Day-of-month OR day-of-week when both are restricted.
        let either = Cron::parse("0 12 13 * 1").unwrap();
        assert_eq!(either.next_after(base), Some(local(2026, 3, 13, 12, 0)));
        let yearly = Cron::parse("0 0 1 1 *").unwrap();
        assert_eq!(yearly.next_after(base), Some(local(2027, 1, 1, 0, 0)));
        assert_eq!(Cron::parse("0 0 31 2 *").unwrap().next_after(base), None);
    }

    #[test]
    fn due_jobs_fire_once_and_only_for_their_directory() {
        let created = local(2026, 3, 10, 10, 2);
        let mut elsewhere = job("other", Some("* * * * *"), None, created);
        elsewhere.cwd = "/elsewhere".into();
        let jobs = vec![
            job("tick", Some("*/5 * * * *"), None, created),
            job("once", None, Some(created + 60), created),
            elsewhere,
        ];
        // Before anything is due.
        let (prompts, kept, changed) = take_due(jobs.clone(), "/work", created + 30);
        assert!(prompts.is_empty() && !changed && kept.len() == 3);
        // 10:05: both fire; the one-shot is removed, the cron remembered.
        let now = local(2026, 3, 10, 10, 5) + 2;
        let (prompts, kept, changed) = take_due(jobs, "/work", now);
        assert_eq!(prompts, ["run tick", "run once"]);
        assert!(changed);
        assert_eq!(
            kept.iter().map(|j| j.id.as_str()).collect::<Vec<_>>(),
            ["tick", "other"]
        );
        // Polled again in the same minute: nothing.
        let (prompts, kept, _) = take_due(kept, "/work", now + 20);
        assert!(prompts.is_empty());
        // And again at 10:10.
        let (prompts, _, _) = take_due(kept, "/work", local(2026, 3, 10, 10, 10));
        assert_eq!(prompts, ["run tick"]);
    }

    #[test]
    fn missed_recurring_runs_are_skipped_and_old_jobs_expire() {
        let created = local(2026, 3, 10, 10, 0);
        let jobs = vec![
            job("daily", Some("0 9 * * *"), None, created),
            job("late-once", None, Some(created + 60), created),
        ];
        // Reopened two days later at noon: the 09:00 runs were missed.
        let now = local(2026, 3, 12, 12, 0);
        let (prompts, kept, changed) = take_due(jobs, "/work", now);
        assert_eq!(prompts, ["run late-once"], "a one-shot still fires, late");
        assert!(changed);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].last, Some(now));
        // Next morning it fires normally.
        let (prompts, kept, _) = take_due(kept, "/work", local(2026, 3, 13, 9, 0) + 5);
        assert_eq!(prompts, ["run daily"]);
        // Eight days after creation it is gone, unless durable.
        let later = created + 8 * 24 * 3600;
        let mut durable = kept[0].clone();
        durable.id = "kept".into();
        durable.durable = true;
        durable.last = Some(later - 60);
        let (_, kept, changed) = take_due(vec![kept[0].clone(), durable], "/work", later);
        assert!(changed);
        assert_eq!(
            kept.iter().map(|j| j.id.as_str()).collect::<Vec<_>>(),
            ["kept"]
        );
    }

    #[test]
    fn the_file_round_trips_and_a_bad_file_is_no_jobs() {
        let home = std::env::temp_dir().join(format!(
            "orbit-sched-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&home).unwrap();
        assert!(load(&home).is_empty());
        let jobs = vec![job("a", Some("0 9 * * *"), None, 100)];
        save(&home, &jobs).unwrap();
        assert_eq!(load(&home), jobs);
        assert!(describe(&jobs[0], 100).starts_with("a · cron `0 9 * * *` · next in"));
        std::fs::write(path(&home), "not json").unwrap();
        assert!(load(&home).is_empty());
    }

    fn failure_home(label: &str) -> PathBuf {
        let home = std::env::temp_dir().join(format!(
            "orbit-sched-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&home).unwrap();
        home
    }

    #[test]
    fn checked_load_and_claim_refuse_invalid_queues_without_changing_them() {
        for kind in ["corrupt", "directory", "oversized"] {
            let home = failure_home(kind);
            assert!(load_checked(&home).unwrap().is_empty());
            match kind {
                "directory" => std::fs::create_dir(path(&home)).unwrap(),
                "oversized" => {
                    std::fs::write(path(&home), vec![b' '; MAX_FILE_BYTES as usize + 1]).unwrap()
                }
                _ => std::fs::write(path(&home), b"{not valid schedule data").unwrap(),
            }
            let before = std::fs::read(path(&home)).ok();
            assert!(load_checked(&home).is_err(), "{kind}");
            assert!(fire_due(&home, "/work", 180).is_err(), "{kind}");
            assert_eq!(std::fs::read(path(&home)).ok(), before, "{kind}");
            assert_eq!(path(&home).is_dir(), kind == "directory");
            std::fs::remove_dir_all(home).unwrap();
        }
    }

    #[test]
    fn malformed_values_are_not_repeated_in_queue_diagnostics() {
        let home = failure_home("diagnostic");
        std::fs::write(
            path(&home),
            br#"{"jobs":[{"id":"one","cwd":"/work","prompt":"run","created":"PRIVATE_PROMPT_MARKER"}]}"#,
        )
        .unwrap();
        let error = load_checked(&home).unwrap_err();
        assert!(error.starts_with("schedules contain invalid job data at line "));
        assert!(!error.contains("PRIVATE_PROMPT_MARKER"));
        std::fs::remove_dir_all(home).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_queue_symlink_is_not_an_empty_queue() {
        let home = failure_home("queue-link");
        let target = home.join("missing-target");
        std::os::unix::fs::symlink(&target, path(&home)).unwrap();
        assert!(load_checked(&home).is_err());
        assert!(fire_due(&home, "/work", 180).is_err());
        assert_eq!(std::fs::read_link(path(&home)).unwrap(), target);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn an_unopenable_lock_never_mutates_or_fires_jobs() {
        let home = failure_home("lock-open");
        save(&home, &[job("once", None, Some(120), 60)]).unwrap();
        let before = std::fs::read(path(&home)).unwrap();
        // Unlike chmod, this fails even when the test runs as root.
        std::fs::create_dir(home.join("schedules.lock")).unwrap();
        let called = std::cell::Cell::new(false);
        let error = locked(&home, || {
            called.set(true);
            save(&home, &[])
        })
        .unwrap_err();
        assert!(error.starts_with("schedules lock could not be opened:"));
        assert!(!called.get());
        assert!(fire_due(&home, "/work", 180).is_err());
        assert_eq!(std::fs::read(path(&home)).unwrap(), before);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn a_failed_flock_never_runs_the_read_decide_write_step() {
        let home = failure_home("flock");
        save(&home, &[job("once", None, Some(120), 60)]).unwrap();
        let before = std::fs::read(path(&home)).unwrap();
        let called = std::cell::Cell::new(false);
        let error = locked_with(
            &home,
            |_| Err("injected flock failure".into()),
            || {
                called.set(true);
                save(&home, &[])
            },
        )
        .unwrap_err();
        assert_eq!(error, "injected flock failure");
        assert!(!called.get());
        assert_eq!(std::fs::read(path(&home)).unwrap(), before);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn a_busy_lock_returns_before_the_holder_releases_it_and_leaves_jobs_pending() {
        let home = failure_home("lock-busy");
        save(&home, &[job("once", None, Some(120), 60)]).unwrap();
        let before = std::fs::read(path(&home)).unwrap();
        let held = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(home.join("schedules.lock"))
            .unwrap();
        rustix::fs::flock(&held, rustix::fs::FlockOperation::LockExclusive).unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let other_home = home.clone();
        let poll = std::thread::spawn(move || {
            sent.send(fire_due(&other_home, "/work", 180)).unwrap();
        });
        // The holder stays locked until after receiving the poll's result.
        // Release even after a timeout so a blocking regression can exit.
        let result = received.recv_timeout(std::time::Duration::from_secs(2));
        let while_held = std::fs::read(path(&home)).unwrap();
        rustix::fs::flock(&held, rustix::fs::FlockOperation::Unlock).unwrap();
        poll.join().unwrap();
        assert_eq!(
            result
                .expect("poll waited for the lock holder")
                .unwrap_err(),
            LOCK_BUSY
        );
        assert_eq!(while_held, before);
        assert_eq!(fire_due(&home, "/work", 180).unwrap(), ["run once"]);
        assert!(fire_due(&home, "/work", 180).unwrap().is_empty());
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn a_failed_save_is_reported_without_delivering_or_consuming_the_prompt() {
        let home = failure_home("save");
        save(&home, &[job("once", None, Some(120), 60)]).unwrap();
        let before = std::fs::read(path(&home)).unwrap();
        let temp = path(&home).with_extension(format!("tmp-{}", std::process::id()));
        std::fs::create_dir(&temp).unwrap();
        assert!(
            fire_due(&home, "/work", 180)
                .unwrap_err()
                .starts_with("schedules:")
        );
        assert_eq!(std::fs::read(path(&home)).unwrap(), before);
        std::fs::remove_dir(temp).unwrap();
        assert_eq!(fire_due(&home, "/work", 180).unwrap(), ["run once"]);
        assert!(fire_due(&home, "/work", 180).unwrap().is_empty());
        std::fs::remove_dir_all(home).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_cannot_stand_in_for_the_schedule_lock() {
        let home = failure_home("lock-link");
        save(&home, &[job("once", None, Some(120), 60)]).unwrap();
        let before = std::fs::read(path(&home)).unwrap();
        let target = home.join("different-file");
        std::fs::write(&target, b"leave intact").unwrap();
        std::os::unix::fs::symlink(&target, home.join("schedules.lock")).unwrap();
        assert!(fire_due(&home, "/work", 180).is_err());
        assert_eq!(std::fs::read(path(&home)).unwrap(), before);
        assert_eq!(std::fs::read(target).unwrap(), b"leave intact");
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn two_sessions_polling_at_once_fire_a_job_once() {
        let home = std::env::temp_dir().join(format!(
            "orbit-sched-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&home).unwrap();
        let created = local(2026, 3, 10, 10, 2);
        let jobs: Vec<Job> = (0..8)
            .map(|n| job(&format!("j{n}"), None, Some(created + 60), created))
            .collect();
        save(&home, &jobs).unwrap();
        let now = created + 120;
        let sessions: Vec<_> = (0..6)
            .map(|_| {
                let home = home.clone();
                std::thread::spawn(move || fire_due(&home, "/work", now))
            })
            .collect();
        let mut fired: Vec<String> = sessions
            .into_iter()
            .flat_map(|session| match session.join().unwrap() {
                Ok(prompts) => prompts,
                Err(error) => {
                    assert_eq!(error, LOCK_BUSY);
                    Vec::new()
                }
            })
            .collect();
        fired.sort();
        let expected: Vec<String> = (0..8).map(|n| format!("run j{n}")).collect();
        assert_eq!(fired, expected, "each job exactly once across all sessions");
        assert!(load(&home).is_empty());
    }
}
