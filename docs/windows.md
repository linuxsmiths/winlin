# Windows HTTP.sys/Schannel server

The Windows server implements the same pairing, discovery, telemetry, synthetic
GET/PUT, and keep-alive API as Linux. Shared logic lives in
`include/winlin/agent.hpp`; only transport, credential storage, cryptography and
OS telemetry differ. The Linux client does not need a different workload format.

This is an initial implementation, not a tuned performance baseline. Native
Windows runtime tests are configured in CI; a successful cross-build on Linux
alone does not validate HTTP.sys behavior.

## Requirements and build

- Windows Server 2022 or Windows 11, x86_64, with TLS 1.3 enabled.
- Windows PowerShell 5.1 or PowerShell 7, running as a 64-bit process.
- Visual Studio 2022 17.6+ C++ build tools, Windows SDK, and CMake 3.24+.
- Network access on the first CMake configure to fetch pinned nlohmann/json,
  unless already supplied as a CMake package.

In PowerShell:

```powershell
# Elevate only if tools must be installed.
.\scripts\prep.ps1
.\scripts\prep.ps1 -Check

# Builds do not require elevation.
.\scripts\build.ps1 server -Jobs 2
ctest --test-dir build -C Release --output-on-failure
```

Prep discovers Visual Studio with `vswhere` and uses either system CMake or the
Visual Studio-bundled copy. Missing tools are installed using Microsoft's
signed Build Tools installer, including recommended C++/SDK components. No
`winget`, vcpkg, OpenSSL, global PATH changes, or Developer Command Prompt is
required. If an installer requests a reboot, reboot and rerun prep.

`build.ps1 all` builds everything available on Windows: server and tests.
`build.ps1 client` explicitly fails because the client is Linux-only.
`-BuildDirectory PATH` keeps separate build configurations; relative paths are
resolved from the calling directory. Builds use x64 MSVC and Release configuration.

Manual CMake builds are also supported:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DWINLIN_BUILD_CLIENT=OFF
cmake --build build --config Release --parallel 2
```

## Configure a test endpoint

HTTP.sys owns TLS termination, so certificates belong in the Windows certificate
store and are bound to an IP/port. Unlike Linux, the server does not read PEM
certificate or private-key files.

From an **elevated** PowerShell terminal, configure a specific local test-network
IPv4 address (use `127.0.0.1` for loopback only):

```powershell
$setup = .\scripts\setup-server.ps1 -BindAddress 10.0.0.4 -Port 8443
$setup | Format-List
```

This imports the bundled **deliberately public** RSA test certificate/key into
`LocalMachine\My` (or reuses the same existing entry), then creates an HTTP.sys
SSL binding and a URL reservation for the current user. Authentication is disabled
by default; no pairing-token file is needed. Optional setup
`-RequireAuthentication` creates a bootstrap credential in
`.winlin-local\pairing-token`. Only the owner, SYSTEM and
Administrators may access credential files. The current user owns the state;
run the server as that same account. Service-account provisioning is not automated.

The PFX import password is intentionally public and is supplied automatically.
This fixture provides **no trustworthy server identity**; anyone can impersonate
it. Do not install it as a trusted root or use it for sensitive traffic. One-time
elevated HTTP.sys provisioning is still required, but no certificate generation,
export, password entry, or client fingerprint copying is needed.

Use `-CertificateThumbprint THUMBPRINT` to select an existing certificate with a
private key in `LocalMachine\My`. This option takes the **40-digit SHA-1 store
identifier**, not the client's SHA-256 certificate pin. `CertificateSha256` in the
script's output is the pin used by the Linux client. The client already recognizes
the bundled fixture; custom certificates require this SHA-256 pin explicitly.

Use `-StateDirectory PATH` for a fresh independent endpoint state. Existing
bindings, URL reservations, and pairing-token files are not silently replaced.
Existing state directories must already be private; setup does not rewrite a
shared directory's permissions. On setup failure, resources created by that
invocation are rolled back.

The binding disables HTTP/2, QUIC, TLS 1.0/1.1 and TLS 1.2 for this endpoint,
without changing machine-wide Schannel policy. Setup does **not** create firewall
rules. Allow the chosen TCP port only from authorized benchmark clients using
your host firewall and VNet configuration. Never expose the agent to the internet.

Start the server (the same user can do this without elevation after setup):

```powershell
.\scripts\run-server.ps1 -BindAddress 10.0.0.4 -Port 8443 -Workers 8
```

The launcher defaults to the repository's `build\Release\winlin-server.exe` with
no authentication. Match `-BindAddress` and `-Port` to the provisioned
endpoint. It never builds, provisions certificates, resets pairing, elevates, or
changes firewall/Schannel policies.

Use `-BuildDirectory PATH`, `-Configuration Debug`, and `-StateDirectory PATH`
for nondefault layouts; supplied relative paths use your current PowerShell
directory. `-ServerExe PATH` selects a binary directly, including single-config
CMake builds. Explicit `-TokenFile FILE` enables authentication, with optional
`-SessionFile FILE` for credential persistence; unspecified tuning options retain
native defaults. Existing credential files are otherwise ignored. `-Help` lists options
without requiring a build or provisioned endpoint. Direct native executable
invocations remain supported.

Only one Winlin server may run per machine, including on different HTTPS ports.
Like Linux, the native server reserves `127.0.0.1:8444` for its lifetime; Winsock
`SO_EXCLUSIVEADDRUSE` prevents sharing. This loopback-only guard carries no
communication, needs no HTTP.sys provisioning or firewall rule, and is released
on exit or crash. An occupied guard port prevents startup. Stop any existing
server before running integration tests.

The Linux launchers' 512K file-descriptor limit does not apply to HTTP.sys/Winsock;
there is no corresponding Windows `RLIMIT_NOFILE` setting to raise.

The backend is `httpsys-schannel`. `--backend httpsys` is accepted explicitly;
OpenSSL/kTLS backend requests fail rather than falling back.

The default cipher is `TLS_AES_128_GCM_SHA256`. To use
`TLS_AES_256_GCM_SHA384`, select it with `-Cipher` in the launcher (native
`--cipher`) and `--cipher` on the Linux client. HTTP.sys reports negotiated
protocol/algorithm/key size; mismatches or
missing information cause request rejection. The server does not claim that
`--cipher` rewrites Schannel's handshake policy. The Linux client offers only
the selected TLS 1.3 suite.

Press Ctrl+C to stop gracefully. For local automation, `-StopFile PATH` (native
`--stop-file PATH`) also requests a graceful stop when that file appears. The file
must not already exist at startup, and remains the caller's responsibility to remove.

## Pair and run from Linux

No authentication setup or file transfer is needed. Verify the certificate
fingerprint through an independent trusted channel if using a custom certificate.
The bundled public certificate needs no fingerprint entry:

```sh
./scripts/run-client.sh pair --host 10.0.0.4 --port 8443 \
  --target .winlin-local/windows.json

./scripts/run-client.sh inspect --target .winlin-local/windows.json
./scripts/run-client.sh run --target .winlin-local/windows.json \
  --method mixed --get-percent 50 --get-size 4KiB --put-size 16KiB \
  --connections 256 --warmup 10 --duration 30 --repetitions 3
```

To opt into authentication, provision with `-RequireAuthentication`, launch with
`-TokenFile .winlin-local\pairing-token`, securely copy that file to the client
(mode `0600`), and pass `--token-file FILE` to CLI `pair`.
Only this explicit token mode consumes the bootstrap credential and creates
`PAIRING-TOKEN-FILE.session` on the server, or the path selected by
`--session-file`. Preserve it across restarts. To reset pairing deliberately,
stop the server, remove that exact session file and the matching Linux target
file, replace the bootstrap credential securely, and restart.

The same interactive Linux menu can register Windows targets. See the
[HTTPS guide](https.md) for workload controls, measurement semantics, and JSON
results.

## Telemetry and comparison caveats

Operation counts, bytes, CPU time, and peak working set use the common result
schema. Context-switch counts and raw accepted/active connection and TLS
handshake counts are not collected on Windows yet; these are explicitly
unavailable and returned as `null`.

**Application-process CPU is not total OS CPU.** HTTP.sys/Schannel can execute
work charged to the System process, outside this server's process counters.
Results record this scope and the client emits a warning. Whole-system and
kernel attribution are needed before comparing total TLS CPU efficiency with
Linux. Neither implementation currently collects that attribution.
Processor-group count is recorded, but worker affinity and group/NUMA placement
are not tuned automatically. Verify scheduling on hosts with more than 64 logical
processors before interpreting scaling results.

HTTP.sys performs native request parsing and buffering; malformed requests can
be rejected by the kernel before reaching the shared agent. Every workload
response explicitly disables HTTP.sys response caching. Both servers reuse a
pre-generated payload and fully consume PUT bodies before acknowledging them.

## Tests

Ordinary Windows tests cover the shared agent, core behavior, native credential
ACL enforcement, process telemetry, and PowerShell helpers. Optional HTTPS tests
need an **elevated** terminal and Python 3:

```powershell
.\scripts\prep.ps1 -IntegrationTests
.\scripts\build.ps1 server -IntegrationTests
ctest --test-dir build -C Release --output-on-failure
```

CTest starts Windows PowerShell with a fresh module search path so its built-in
modules load correctly even when CTest is invoked from PowerShell 7.

These tests provision a temporary certificate/binding/URL reservation on an
ephemeral loopback port, exercise the same HTTP contract as Linux, test
concurrent/persistent GET/PUT, TLS/cipher rejection, and pairing across restarts,
then remove their own resources. They do not change global cipher policy.

For intentional manual endpoint removal, stop the server first and delete only
its configured URL reservation and binding:

```powershell
netsh http delete urlacl url=https://10.0.0.4:8443/
netsh http delete sslcert ipport=10.0.0.4:8443
```

Remove the specific test certificate from `LocalMachine\My` only if you created
it for this endpoint and no other endpoint uses it. Credential/state file removal
and certificate rotation should be deliberate; prep/build never reset pairing.
