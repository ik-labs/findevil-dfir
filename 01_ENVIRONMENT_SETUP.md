# 01 — Environment Setup (Bring-Up Runbook)

> Living doc. As you run each step, record what ACTUALLY worked vs. what was documented.
> Commands below are sourced from the official SANS/teamdfir repos (June 2026), but
> installer details drift — if a command fails, check the source repo and update here.

## 0. The platform reality (read before provisioning)
- SIFT ships primarily as an **OVA** (a full VM). On a VPS you generally **cannot** run a
  nested VM cleanly. So we do **NOT** import the OVA. Instead we install SIFT's tools
  **onto a plain Ubuntu host** using `cast`.
- Protocol SIFT then installs **on top of** that SIFT-ified Ubuntu.

## 1. Provision (AWS Lightsail)
- **Ubuntu 22.04 LTS** (do NOT pick 24.04 — SIFT targets 22.04; avoid dependency breakage).
- Sizing target: **16 GB RAM / 4 vCPU / ~100+ GB disk** minimum for ROCBA.
  (Lightsail's larger instances or a sized EC2 box. 80 GB is the floor; 100+ comfortable.)
  Storage math: 22 GB e01 + ~6–8 GB extracted memory + e01→raw expansion (can balloon
  toward full uncompressed drive) + SIFT tools + multi-GB timelines + scratch.
- Open SSH. You're reaching it via **Twingate** from your Mac, running **Claude Code on the
  Mac** pointed at this box. Confirm you can `ssh` in through Twingate before anything else.

## 2. System prep
```bash
sudo apt update && sudo apt -y upgrade
sudo apt -y install curl wget unzip git build-essential python3-pip jq
# sanity
lsb_release -a        # confirm 22.04
nproc && free -h && df -h   # confirm CPU / RAM / disk headroom
```

## 3. Install SIFT via cast (modern path; sift-cli is deprecated)
`cast` is the successor to `sift-cli` (sift-cli officially deprecated 2023-03-01).
Install `cast` first, then install SIFT. Server mode = tools only, no desktop GUI
(correct for a headless VPS).

```bash
# Install cast (verify latest install instructions at github.com/teamdfir/sift-saltstack)
# cast is a single golang binary. Follow the repo's current "install cast" step, then:
sudo cast install --mode=server teamdfir/sift-saltstack
```
- `--mode=server` → installs tools/packages without desktop modifications. Right for VPS.
- Default SIFT user is `sansforensics` on the prebuilt VM; on your own Ubuntu you're
  installing as your own user — note which user owns the SIFT config.
- **VERIFY on the box:** the exact cast install command and any cosign signature-validation
  step from github.com/teamdfir/sift-saltstack and github.com/teamdfir/sift-cli. Record the
  exact commands you actually ran in 05_BUILD_LOG.md.

## 4. Sanity-check SIFT tools
```bash
which vol.py || which vol           # Volatility
which fls mmls mactime              # Sleuth Kit
which log2timeline.py psort.py      # plaso (super-timeline)
which ewfmount                      # for mounting .e01
```
If any are missing, the SIFT install didn't complete — re-run / check logs before moving on.

## 5. Install Protocol SIFT (the baseline we're improving)
Official one-liner (run AFTER SIFT is up):
```bash
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
```
- Read what the script installs before trusting the baseline. Record its components.
- Find where Protocol SIFT keeps its agent loop / prompts / tool wrappers — that's what
  our MCP server will sit alongside or replace.

## 6. Get the ROCBA evidence (download order matters)
Download the **memory zip first** (smaller, validates your pipeline), then the disk image.
```bash
mkdir -p ~/cases/rocba/{evidence,work,output}
cd ~/cases/rocba/evidence
# Pull Rocba-Memory.zip (5.3 GB) from the Egnyte share, then:
unzip Rocba-Memory.zip          # peek: raw? .mem? .dmp? crash dump? -> tells Volatility how to read it
# Then pull rocba-cdrive.e01 (22 GB)
ls -lh                          # confirm both present, sizes sane
```
- **Keep evidence/ pristine and read-only.** Never let any tool write here.
```bash
chmod -R a-w ~/cases/rocba/evidence   # belt-and-suspenders read-only
```

## 7. Mount the disk image READ-ONLY (never touch the original)
```bash
# .e01 -> raw via ewfmount, then loop-mount read-only. Exact flags: verify on box.
mkdir -p ~/cases/rocba/work/ewf ~/cases/rocba/work/mnt
ewfmount ~/cases/rocba/evidence/rocba-cdrive.e01 ~/cases/rocba/work/ewf
# inspect partitions, then loop mount the NTFS partition read-only:
mmls ~/cases/rocba/work/ewf/ewf1
# sudo mount -o ro,loop,offset=<bytes>,show_sys_files ~/cases/rocba/work/ewf/ewf1 ~/cases/rocba/work/mnt
```
Record the exact offset/flags that worked. This read-only discipline IS your evidence-
integrity story for component #6 — document it as you do it.

## 8. Point Volatility at the memory image
```bash
# Identify profile/symbols first (Vol3 auto-detects; Vol2 needs imageinfo).
vol.py -f ~/cases/rocba/evidence/<memory-file> windows.info   # Vol3 example
```
Record: Volatility version, the memory file format, the working invocation. This is the
memory half of the spine.

## 9. Verify Claude Code → box loop
From your Mac (through Twingate), confirm Claude Code can run commands on this box and read
these docs. Drop this whole doc set at `~/cases/rocba/docs/` so the agent has its source of
truth co-located with the work.

## Definition of "environment ready"  — DONE 2026-06-12
- [x] SIFT tools present (Volatility 3 `vol`, Sleuth Kit, plaso, ewfmount, 7z)
- [x] Protocol SIFT installed; baseline agent runs
      → installed YES; **agent run pending Claude Code auth on box** (the one open item)
- [x] Both ROCBA files downloaded; evidence/ is read-only
- [x] Disk image mounts read-only; Volatility reads the memory image
- [x] Claude Code on Mac can drive the box and read /docs
Only after ALL boxes checked → proceed to 02_BASELINE_OBSERVATION.md

## What ACTUALLY worked (deltas from the plan above)
- **Access:** pem-key SSH alias `rocba` → static IP 13.235.157.16 (not Twingate). Box is
  Ubuntu 22.04.5, 4 vCPU / 15 GiB / ~309 GB free. I drive it from the Mac via `ssh rocba`.
- **cast:** v1.0.19 `.deb` from github.com/ekristen/cast (cosign-verified by cast itself);
  `sudo cast install --mode=server teamdfir/sift-saltstack` → 724/724 states, failed=0.
- **Vol3 path:** it's `/usr/local/bin/vol` (v2.28.0) — there is NO `vol.py`. The baseline
  CLAUDE.md's "/opt/volatility3-2.20.0/vol.py" note is stale. Run with `2>/dev/null` (Vol
  spams Progress to stderr via `\r`).
- **Evidence:** downloaded direct-to-box from the Egnyte `/dd/?entryId=` links (public, no
  auth). Memory is NESTED: `Rocba-Memory.zip` → `Rocba-Memory.7z` → `Rocba-Memory.raw` (18 GB).
- **Disk is a single NTFS volume** (no MBR/GPT): `mmls` fails, `fsstat ewf1` works at offset 0.
- **Mount fix (non-obvious):** ntfs-3g failed "Failed to read last sector" (image truncated
  ~6 sectors short of the NTFS-declared size; no `ntfs3` kernel module on the AWS kernel).
  Fixed read-only with a `dm-linear` that pads 64 zero sectors over a read-only loop:
  ```bash
  LOOP=$(sudo losetup --read-only --find --show ~/cases/rocba/work/ewf/ewf1)
  SZ=$(sudo blockdev --getsz "$LOOP")
  printf "0 %s linear %s 0\n%s 64 zero\n" "$SZ" "$LOOP" "$SZ" | sudo dmsetup create rocba_ntfs
  sudo mount -o ro,show_sys_files,streams_interface=windows /dev/mapper/rocba_ntfs ~/cases/rocba/work/mnt
  ```
  Every layer is read-only; write attempt → "Read-only file system". For most parsing we use
  TSK directly on `ewf1` anyway (no kernel NTFS driver in the path).
- **Memory facts:** Win10 build 19041 x64, 4 CPUs, SystemTime 2020-11-16 02:32:38 UTC (capture
  is 3 days AFTER the 11-13 break-in; Fred's vacation 11-10→11-13 precedes it).
