# Galaxy Tab S11 Root My Galaxy port — phone-only GitHub Actions

This directory is a temporary controller for porting `BuSung-dev/Root-My-Galaxy-Payloads` to the Galaxy Tab S11 without requiring a local PC.

Target currently being prepared:

- model: `SM-X730` (Galaxy Tab S11 Wi-Fi / `gts11wifi`)
- reported kernel family: `6.6.102`
- requested firmware/build hint: `BZG3`

The upstream device-request issue says the Tab S11 BZG3 July build uses the same or a similar kernel version as the A56. That is useful as a reference only. The workflow does **not** copy A56 offsets or physical-address assumptions into the Tab S11 target.

## Workflow 1 — firmware + offline kernel analysis

Run **Actions → Tab S11 - Prepare Root My Galaxy port → Run workflow**.

Inputs:

- `model`: default `SM-X730`.
- `region`: Samsung CSC used by FUS. Change this to the CSC that contains the exact target firmware.
- `firmware_version`: best option when the exact 3/4-part FUS version is known. Leave empty to select by `build_hint`.
- `build_hint`: default `BZG3`.
- `keep_vmlinux`: keep enabled for the first porting run.

The workflow performs these operations entirely on the GitHub-hosted Ubuntu runner:

1. installs `samloader`, LLVM, `bpftool`, `pahole`, LZ4 and `vmlinux-to-elf`;
2. queries Samsung FUS and resolves the exact requested firmware;
3. downloads the official firmware from Samsung;
4. extracts AP/BL and `boot.img`;
5. extracts the exact raw ARM64 kernel Image;
6. reconstructs `vmlinux.elf` and `vmlinux.nm`;
7. validates/extracts the embedded raw BTF blob;
8. produces raw/C BTF dumps;
9. collects the required Root My Galaxy symbol offsets that can be derived safely from the exact ELF;
10. saves `worker_thread` disassembly and trace-event symbol evidence;
11. extracts bootloader evidence needed to derive the physical load address;
12. uploads a 7-day `port-bundle` artifact;
13. deletes the multi-gigabyte Samsung firmware before artifact upload.

Important files in the artifact:

- `kernel`
- `kernel.sha256`
- `vmlinux.elf`
- `vmlinux.nm`
- `vmlinux.btf`
- `vmlinux-btf.raw`
- `vmlinux-btf.h`
- `worker_thread.objdump`
- `key-symbols.txt`
- `analysis.json`
- `PORT_REPORT.md`
- bootloader evidence files
- exact FUS version and provenance files

## Why the port is staged

The upstream exploit contains target-specific values that cannot be responsibly inferred from the three-part kernel version alone. In particular, physical load mapping, some special data-object offsets, pselect overlap, trace-event numbering, P0 fingerprint/probe selection, and runtime exploit behavior must be derived or validated for the exact Tab S11 firmware.

The phone-only workflow is therefore:

1. run the preparation Action;
2. inspect the generated artifact/logs from GitHub (or let ChatGPT inspect the run);
3. generate/commit the Tab S11 `target.h` and `p0_fingerprint.h` on this branch;
4. run the payload-build Action;
5. build/audit the exact Samsung KernelSU module and `ksud` in Actions;
6. update the support manifest and build the Root My Galaxy APK in Actions;
7. perform only the final hardware validation on the tablet.

No desktop Linux/Windows environment is required for the offline steps.
