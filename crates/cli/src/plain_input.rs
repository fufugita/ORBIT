//! Synchronous plain input with cooperative cancellation and no read-ahead.

#![forbid(unsafe_code)]

use orbit_provider_http::CancelToken;
use std::io;

#[derive(Debug, PartialEq, Eq)]
pub enum PlainInput {
    Line(String),
    Eof,
    Cancelled,
}

/// Read one line from the plain frontend's exclusively consumed stdin.
///
/// Callers must use this boundary for both commands and approvals, without a
/// concurrent reader or a buffered stdin iterator that may retain later bytes.
/// Unix waits observe cancellation without changing descriptor or terminal
/// flags. The non-Unix fallback retains ordinary blocking stdin behavior.
pub fn read_stdin_line(cancel: &CancelToken) -> io::Result<PlainInput> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        let stdin = io::stdin();
        read_fd_line(stdin.as_fd(), cancel)
    }
    #[cfg(not(unix))]
    {
        if cancel.is_cancelled() {
            return Ok(PlainInput::Cancelled);
        }
        let mut line = String::new();
        let count = io::stdin().read_line(&mut line)?;
        if cancel.is_cancelled() {
            return Ok(PlainInput::Cancelled);
        }
        if count == 0 {
            return Ok(PlainInput::Eof);
        }
        let mut bytes = line.into_bytes();
        let newline = bytes.last() == Some(&b'\n');
        if newline {
            bytes.pop();
        }
        finish_line(bytes, newline)
    }
}

fn finish_line(mut bytes: Vec<u8>, newline: bool) -> io::Result<PlainInput> {
    // BufRead::lines removes CR only as part of a terminating CRLF pair.
    if newline && bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    String::from_utf8(bytes)
        .map(PlainInput::Line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "input is not valid UTF-8"))
}

#[cfg(unix)]
fn read_fd_line(fd: std::os::fd::BorrowedFd<'_>, cancel: &CancelToken) -> io::Result<PlainInput> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::io::{Errno, read};

    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 50_000_000,
    };
    let mut bytes = Vec::new();
    loop {
        if cancel.is_cancelled() {
            return Ok(PlainInput::Cancelled);
        }
        let mut descriptors = [PollFd::from_borrowed_fd(fd, PollFlags::IN)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => continue,
            Ok(_) => {}
            Err(error) if error == Errno::INTR => continue,
            Err(error) => return Err(error.into()),
        }
        if cancel.is_cancelled() {
            return Ok(PlainInput::Cancelled);
        }
        let ready = descriptors[0].revents();
        if ready.contains(PollFlags::NVAL) {
            return Err(Errno::BADF.into());
        }
        if ready.contains(PollFlags::ERR) {
            return Err(io::Error::other("input descriptor reported an I/O error"));
        }
        if !ready.intersects(PollFlags::IN | PollFlags::HUP) {
            continue;
        }
        // A single synchronous reader consumes one ready byte. Reading a whole
        // line here could block on a partial pipe line despite poll readiness.
        // HUP still permits draining remaining data before read reports EOF.
        let mut byte = [0u8; 1];
        let count = match read(fd, &mut byte[..]) {
            Ok(count) => count,
            Err(error) if error == Errno::INTR || error == Errno::AGAIN => continue,
            Err(error) => return Err(error.into()),
        };
        if cancel.is_cancelled() {
            return Ok(PlainInput::Cancelled);
        }
        if count == 0 {
            return if bytes.is_empty() {
                Ok(PlainInput::Eof)
            } else {
                finish_line(bytes, false)
            };
        }
        if byte[0] == b'\n' {
            return finish_line(bytes, true);
        }
        bytes.try_reserve(1).map_err(|_| {
            io::Error::new(io::ErrorKind::OutOfMemory, "cannot allocate input line")
        })?;
        bytes.push(byte[0]);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use rustix::io::ioctl_fionread;
    use std::io::Write;
    use std::os::fd::{AsFd, AsRawFd};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn pre_cancelled_input_consumes_no_ready_bytes_and_keeps_the_descriptor_open() {
        let (reader, mut writer) = io::pipe().unwrap();
        writer.write_all(b"keep\n").unwrap();
        let cancel = CancelToken::new();
        cancel.cancel();
        assert_eq!(
            read_fd_line(reader.as_fd(), &cancel).unwrap(),
            PlainInput::Cancelled
        );
        assert_eq!(ioctl_fionread(&reader).unwrap(), 5);
        assert_eq!(
            read_fd_line(reader.as_fd(), &CancelToken::new()).unwrap(),
            PlainInput::Line("keep".into())
        );
    }

    #[test]
    fn queued_lines_are_not_prefetched_and_descriptor_flags_do_not_change() {
        let (reader, mut writer) = io::pipe().unwrap();
        writer.write_all(b"one\ntwo\n").unwrap();
        let descriptor = reader.as_raw_fd();
        let flags = rustix::fs::fcntl_getfl(&reader).unwrap();
        let cancel = CancelToken::new();
        assert_eq!(
            read_fd_line(reader.as_fd(), &cancel).unwrap(),
            PlainInput::Line("one".into())
        );
        assert_eq!(ioctl_fionread(&reader).unwrap(), 4);
        assert_eq!(reader.as_raw_fd(), descriptor);
        assert_eq!(rustix::fs::fcntl_getfl(&reader).unwrap(), flags);
        assert_eq!(
            read_fd_line(reader.as_fd(), &cancel).unwrap(),
            PlainInput::Line("two".into())
        );
        assert_eq!(ioctl_fionread(&reader).unwrap(), 0);
    }

    #[test]
    fn crlf_blank_embedded_cr_and_final_unterminated_cr_match_lines_semantics() {
        let (reader, mut writer) = io::pipe().unwrap();
        writer.write_all(b"\r\nhello\r\none\rtwo\nlast\r").unwrap();
        drop(writer);
        let cancel = CancelToken::new();
        for expected in ["", "hello", "one\rtwo", "last\r"] {
            assert_eq!(
                read_fd_line(reader.as_fd(), &cancel).unwrap(),
                PlainInput::Line(expected.into())
            );
        }
        assert_eq!(
            read_fd_line(reader.as_fd(), &cancel).unwrap(),
            PlainInput::Eof
        );
        assert_eq!(
            read_fd_line(reader.as_fd(), &cancel).unwrap(),
            PlainInput::Eof
        );
    }

    #[test]
    fn utf8_errors_are_distinct_from_eof_and_do_not_consume_the_following_line() {
        let (reader, mut writer) = io::pipe().unwrap();
        writer.write_all("héλ\n".as_bytes()).unwrap();
        writer.write_all(b"\xff\nnext\n\xe2\x82").unwrap();
        drop(writer);
        let cancel = CancelToken::new();
        assert_eq!(
            read_fd_line(reader.as_fd(), &cancel).unwrap(),
            PlainInput::Line("héλ".into())
        );
        assert_eq!(
            read_fd_line(reader.as_fd(), &cancel).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read_fd_line(reader.as_fd(), &cancel).unwrap(),
            PlainInput::Line("next".into())
        );
        assert_eq!(
            read_fd_line(reader.as_fd(), &cancel).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read_fd_line(reader.as_fd(), &cancel).unwrap(),
            PlainInput::Eof
        );
    }

    #[test]
    fn closed_writer_drains_all_hup_bytes_before_reporting_eof() {
        let (reader, mut writer) = io::pipe().unwrap();
        writer.write_all(b"first\nfinal").unwrap();
        drop(writer);
        assert_eq!(ioctl_fionread(&reader).unwrap(), 11);
        let cancel = CancelToken::new();
        assert_eq!(
            read_fd_line(reader.as_fd(), &cancel).unwrap(),
            PlainInput::Line("first".into())
        );
        assert_eq!(ioctl_fionread(&reader).unwrap(), 5);
        assert_eq!(
            read_fd_line(reader.as_fd(), &cancel).unwrap(),
            PlainInput::Line("final".into())
        );
        assert_eq!(
            read_fd_line(reader.as_fd(), &cancel).unwrap(),
            PlainInput::Eof
        );
    }

    #[test]
    fn cancellation_finishes_with_an_empty_open_pipe_without_needing_eof() {
        let (reader, writer) = io::pipe().unwrap();
        let cancel = CancelToken::new();
        std::thread::scope(|scope| {
            let writer = writer;
            let (started, entered) = mpsc::channel();
            let (send, result) = mpsc::channel();
            let fd = reader.as_fd();
            let token = &cancel;
            let worker = scope.spawn(move || {
                started.send(()).unwrap();
                send.send(read_fd_line(fd, token)).unwrap();
            });
            entered.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(matches!(result.try_recv(), Err(mpsc::TryRecvError::Empty)));
            cancel.cancel();
            let observed = result.recv_timeout(Duration::from_secs(2));
            // Keep the actual writer open until cancellation was observed;
            // dropping it also releases a bad blocking reader before join.
            drop(writer);
            worker.join().unwrap();
            assert_eq!(observed.unwrap().unwrap(), PlainInput::Cancelled);
        });
    }

    #[test]
    fn cancellation_discards_an_actually_consumed_partial_utf8_line() {
        let (reader, mut writer) = io::pipe().unwrap();
        writer.write_all(b"partial \xe2\x82").unwrap();
        let cancel = CancelToken::new();
        std::thread::scope(|scope| {
            let mut writer = writer;
            let (send, result) = mpsc::channel();
            let fd = reader.as_fd();
            let token = &cancel;
            let worker = scope.spawn(move || {
                send.send(read_fd_line(fd, token)).unwrap();
            });
            let end = Instant::now() + Duration::from_secs(2);
            while ioctl_fionread(&reader).unwrap() != 0 {
                assert!(
                    Instant::now() < end,
                    "partial input was not actually consumed"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(matches!(result.try_recv(), Err(mpsc::TryRecvError::Empty)));
            cancel.cancel();
            let observed = result.recv_timeout(Duration::from_secs(2));
            if observed.is_err() {
                drop(writer);
                worker.join().unwrap();
                panic!("partial input cancellation deadline");
            }
            worker.join().unwrap();
            assert_eq!(observed.unwrap().unwrap(), PlainInput::Cancelled);
            writer.write_all(b"fresh\n").unwrap();
            assert_eq!(
                read_fd_line(reader.as_fd(), &CancelToken::new()).unwrap(),
                PlainInput::Line("fresh".into())
            );
        });
    }

    #[test]
    fn continuously_ready_pipe_input_does_not_starve_cancellation() {
        let (reader, writer) = io::pipe().unwrap();
        let original_flags = rustix::fs::fcntl_getfl(&writer).unwrap();
        rustix::fs::fcntl_setfl(&writer, original_flags | rustix::fs::OFlags::NONBLOCK).unwrap();
        let cancel = CancelToken::new();
        struct CancelOnDrop(CancelToken);
        impl Drop for CancelOnDrop {
            fn drop(&mut self) {
                self.0.cancel();
            }
        }
        let written = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            let _cleanup = CancelOnDrop(cancel.clone());
            let produced = written.clone();
            let token = &cancel;
            let producer = scope.spawn(move || {
                let writer = writer;
                let bytes = [b'x'; 512];
                while !token.is_cancelled() {
                    match rustix::io::write(&writer, &bytes) {
                        Ok(count) => {
                            produced.fetch_add(count, Ordering::SeqCst);
                        }
                        Err(error)
                            if error == rustix::io::Errno::AGAIN
                                || error == rustix::io::Errno::INTR =>
                        {
                            std::thread::yield_now()
                        }
                        Err(error) => panic!("owned pipe write failed: {error}"),
                    }
                }
            });
            let (send, result) = mpsc::channel();
            let fd = reader.as_fd();
            let token = &cancel;
            let consumer = scope.spawn(move || {
                send.send(read_fd_line(fd, token)).unwrap();
            });
            let end = Instant::now() + Duration::from_secs(3);
            loop {
                if written.load(Ordering::SeqCst) >= 32 * 1024
                    && ioctl_fionread(&reader).unwrap() > 0
                {
                    break;
                }
                assert!(
                    Instant::now() < end,
                    "ready input did not make actual progress"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            cancel.cancel();
            let observed = result.recv_timeout(Duration::from_secs(2));
            producer.join().unwrap();
            consumer.join().unwrap();
            assert_eq!(observed.unwrap().unwrap(), PlainInput::Cancelled);
        });
    }

    #[test]
    fn a_write_only_pipe_error_is_not_a_clean_eof() {
        let (reader, writer) = io::pipe().unwrap();
        drop(reader);
        let error = read_fd_line(writer.as_fd(), &CancelToken::new()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }
}
