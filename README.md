# Timing based read detection example

The following was inspired by [Nick Peterson's tweet](https://twitter.com/nickeverdox/status/1476295914423656456).

It's a quick attempt at recreating what he did and looking for evasion techniques, in the span of under 3 hours. It is far from complete, and definitely not robust.

## Main Assumption

I assume Nick used memory access timing side channel, which means repeated memory access are supposed to be quicker than the first, uncached one. By intentionally flushing the memory region from the cache, it could be possible to detect unexpected memory access to the region.

## Running

You will need memflow connectors/OS layers set up. If testing locally, install [`memflow-native`](https://github.com/memflow/memflow-native/). If testing against VM, install [`memflow-kvm`](https://github.com/memflow/memflow-kvm/) and [`memflow-win32`](https://github.com/memflow/memflow-win32/).

`cargo run --release --bin side-channel-client -- 315` to run the client. Adjust the 315 cycle value if needed, which is the detection threshlold.

The binary will print the buffer's address, do supply it to the attacker binary:

`cargo run --release --bin side-channel-attacker -- -o native --address <previously printed address>`

If the client is running on windows, you will need to also supply `-p side-channel-client.exe` argument.

If testing against a VM, you will need to replace `-o native` with `-c kvm -o win32` chain.

## Key takeaways

- Timing is not super reliable due to possible interrupts in the middle of operations (would probably need to go kernel space route). This usually leads to false negatives, unless timing is tuned improperly.

- With memory mapped I/O it is possible to do a cache flush and avoid detection. Modify [memflow's MappedPhysicalMemory connector](https://github.com/memflow/memflow/blob/next/memflow/src/connector/mmap.rs#L151):

```rust
fn phys_read_raw_iter<'b>(
    &mut self,
    data: CIterator<PhysicalReadData<'b>>,
    out_fail: &mut ReadFailCallback<'_, 'b>,
) -> Result<()> {
    for MemData(mapped_buf, mut buf) in self.info.as_ref().map_iter(data, out_fail) {
        buf.copy_from_slice(mapped_buf.as_ref());
        unsafe { core::arch::x86_64::_mm_clflush(mapped_buf.as_ptr()) };
    }
    Ok(())
}
```

- x86's nocache page bit on remapped pages does not seem to have an effect on timing detection evasion.

