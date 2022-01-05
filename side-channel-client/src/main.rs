use core::arch::x86_64::{__rdtscp, _mm_clflush, _mm_lfence};

#[no_mangle]
pub static mut SC_BUFFER: [u64; 4096 / 8] = [0; 4096 / 8];

#[inline(always)]
unsafe fn time(junk: &mut u32) -> u64 {
    _mm_lfence();
    let ret = __rdtscp(junk);
    _mm_lfence();
    ret
}

fn main() {
    let buf: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(SC_BUFFER.as_mut_ptr() as *mut _, 4096) };

    println!("Monitored buffer: {:p}", buf.as_ptr());

    let threshold = std::env::args()
        .last()
        .and_then(|v| str::parse(&v).ok())
        .unwrap_or(315);

    let mut junk = 0u32;

    let mut detections = 0;

    let mut times = std::collections::VecDeque::new();

    let mut start = std::time::Instant::now();

    for i in 0.. {
        // Flush cache
        unsafe { _mm_clflush(buf.as_ptr()) };

        std::thread::sleep(std::time::Duration::from_millis(1));

        // Starting timestamp
        let t1 = unsafe { time(&mut junk) };

        // Perform read access
        let _ = unsafe { core::ptr::read_volatile(buf.as_ptr()) };

        // Ending timestamp
        let t2 = unsafe { time(&mut junk) };

        // Write detections into the buffer!
        unsafe { core::ptr::write(buf.as_mut_ptr() as _, detections) };

        if i > 0 && t2 - t1 < threshold {
            detections += 1;
            println!("{} MATCH {} | {}", i, t2 - t1, detections);
        }

        times.push_back(t2 - t1);

        if times.len() > 1000 {
            times.pop_front();
        }

        if start.elapsed().as_secs_f64() > 1.0 {
            let median = if times.len() > 0 {
                let mut buf = times.iter().copied().collect::<Vec<_>>();
                buf.sort();
                buf[buf.len() / 2]
            } else {
                0
            };

            println!(
                "MA 1s {}, Median {}",
                times.iter().copied().sum::<u64>() as f64 / times.len() as f64,
                median
            );
            start = std::time::Instant::now();
        }
    }
}
