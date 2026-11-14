# The Silicon & Local Network Mesh: how it fits KOS

**Status: partly implemented (phases 1, 2 and the sync half of 3); the rest is still design only.**
Built and tested: pairing and identity, an encrypted authenticated link over an ordinary network
(loopback tested), and sync over that link: `kos/linkdev.py`, `kos/syncer.py`, `kos/migrate.py`, the
`devices.*` / `sync.*` / `migrate.*` apps, and the wire format in `docs/SYNC.md`. What was decided on the
way, against the four decisions at the bottom of this file:

1. **Crypto dependency: yes.** `cryptography` was already a requirement; the link uses only its vetted
   primitives (Ed25519, X25519, HKDF-SHA256, ChaCha20-Poly1305). No cipher of our own.
2. **Firmware gate: untouched.** Nothing here uses a radio. A link is TCP to an address and port, behind a
   firewall rule. Phase 4 (Bluetooth, UWB, proximity) is not started and still needs this decision.
3. **No central account.** Pairing is in person: the same 6-digit code on both screens and the password on both.
4. **KOS-to-KOS is what is enforced.** A peer that is not KOS is a remote party holding a key (see `docs/SYNC.md`
   for what a native client must do itself).

One thing differs from the proposal below: the owner asked for a linked device to have *every* permission of
the other. That is built as "may **ask** for any action" (the receiving owner still types the password, per
rule 1), minus the few actions that would let one device re-root trust on the other (`NEVER_REMOTE` in
`kos/linkdev.py`). **Not built:** proximity, handoff of app state, camera, tether, any radio, any client that is not
KOS. The text below is the original design and is kept as written; where it disagrees with this paragraph, this
paragraph is newer. Per the README gaps table, anything not listed as built above must not be described as a feature.

The sketch has four parts: (1) cryptographic trust and identity, (2) proximity
discovery, (3) direct peer-to-peer transport, (4) resource sharing (remote camera,
cellular tunnel). It is the "Continuity" idea: your devices notice each other and
cooperate. KOS can do a version of it. It cannot do the sketch as written, because
several sentences in the sketch are the exact things KOS's rules forbid.

## Scope limit that applies to everything below

KOS's guarantees hold only where KOS runs. A mesh peer that is a phone running another
OS is *not* under KOS's password, sandbox, audit log or firewall. Everything a KOS
machine receives from such a peer is hostile input, and nothing KOS promises about
"the other device" is true. The only honest mesh is KOS-to-KOS; any other peer is
a remote party with a key.

## Where the sketch conflicts with KOS

Read these first. They decide the design.

| Sketch says | KOS rule it hits | Resolution proposed here |
|---|---|---|
| Devices share keys via "a central secure account" | No cloud, no cached logins; the trust root is the owner's password | Pair in person: both screens show a short code, the owner types the password on both ends. Keys are generated and stay local. A central account is a third party holding the trust root; I recommend against it. |
| "Hardware enclave" challenge-response | KOS has no secure enclave | Private key sealed in the TPM 2.0 where present, else in the kernel keyring + LUKS, as the volume key already is. Say which one in `kos doctor`; never claim an enclave. |
| Radios are on, bound and beaconing | **Firmware gate**: `FIRMWARE_CLASSES` in `kos/firmware.py` treats wireless/Bluetooth/network controllers as blocking firmware chips. Wireless is unbound and asked for D3cold at boot (`POWER_OFFABLE`) | Direct contradiction. The mesh needs these chips bound. Either the owner boots `kos.firmware=warn` (the alert stays on every boot) or the mesh does not exist on that machine. This is an owner decision, not a coding detail. |
| "Continuous, low-overhead ambient" beaconing | "No background services, no cached logins, no autostart" (README, line 5) | No resident beacon. Radios are used only while a mesh app the owner started is running, and stop when it exits. There is no "always aware" mode. |
| Beacons broadcast state such as "active document open" | Privacy; rule 4 | Rotating identifiers do not fix this: the *content* of a state beacon is the leak. The beacon carries only a rotating identifier resolvable by paired peers. State travels afterwards over the encrypted link. |
| Direct link "bypassing local router networks completely" | Rule 3: every connection blocked by default, allowed only by a firewall rule, logged | Bypassing the router does not bypass KOS. The OS owns the radio; apps never see a socket. Each peer link is a firewall rule (peer key, port, protocol) created with a password, and every attempt is audited. |
| Phone camera streamed in as "a native system camera" | Apps never open devices; only the OS touches hardware | No virtual `/dev/video`. The OS receives frames and gives them to an app through the protocol (see the existing "Audio / video / camera channel" backlog item). |
| Phone modem tunneled "without the user ever waking the phone screen or interacting" | Rule 1: every action needs the password for *that* action; privileges asked at the moment of use | Rejected as written. See "Resource sharing" below for the version that fits. |
| State "piped directly into the receiving device's active RAM" | Every app message is hostile; OS never writes into app memory | Rejected. The OS delivers a size-limited, schema-checked `handoff` command to an app that asked for it. The app decides what to do with it. |
| Mutual auth "before opening ports" | Matches rule 3 | Kept: the listener exists only after a pairing record is present and a firewall rule allows it. |

## 1. Trust and identity

* **Pairing.** One action, `mesh.pair` (new entry in `ACTIONS`, `authorize` first).
  Both machines show a short authentication string derived from the key exchange;
  the owner confirms it matches and types the password on each. A pairing record
  holds the peer's public key, a name, and the capabilities granted. No manual key
  typing, no network discovery of unknown peers.
* **Identity key.** One long-term key pair per machine, sealed as above. Per-peer
  session keys come from the handshake; a stolen session key must not be a
  long-term key.
* **Revocation.** `mesh.unpair` is a password action, removes the record, and the
  firewall rule with it. Unpair works with the peer offline.
* **Rotation.** Radio-level identifiers (Wi-Fi MAC, Bluetooth address) rotate, and
  paired peers can recognise the next one because it is derived from a shared key.
  KOS has no Bluetooth or Wi-Fi stack of its own and ships no BlueZ or
  NetworkManager (MAC randomisation normally lives there), so this is real work,
  not a setting.
* **Crypto.** The README says: do not invent a cipher, and ask before adding a
  dependency. The standard library has no authenticated encryption or key agreement.
  A Noise-style handshake (static keys pinned at pairing, so no certificates and no
  trust-on-first-use afterwards) over a vetted library is the right design. **I have
  not added a library.** That is decision 1 below.

## 2. Proximity

* **Order of operations.** Rotating beacon wakes a paired peer, then distance is
  checked, then the encrypted link comes up. Proximity only *suggests* an action
  ("offer handoff"); it never authorises one. Being next to a laptop is not a
  password.
* **UWB is an input, not a gate.** Time-of-flight distance can be relayed or spoofed
  unless the ranging is secured (802.15.4z-style scrambled timestamps). I have not
  verified what Linux or this repo's kernel config (`kernel/kos.config`) supports for
  UWB hardware, and nothing in `kos/devices.py` touches UWB. Treat "triggers only
  fire when the devices are next to each other" as unproven until it is tested on
  real hardware.
* **Hand-up of the radio.** "Spin up a higher-bandwidth Wi-Fi link in anticipation of
  data transfer" is a connection and falls under the firewall rule above. Spinning it
  up on a guess, before the owner has asked for anything, is the kind of thing
  rule 3 says to ask first.

## 3. Transport and handoff

* A peer link is a new kind of channel between separate parties, so rule 5 applies in
  full: encrypted and authenticated, or it does not exist. It is **not** the existing
  `Channel` in `kos/protocol.py` (plain JSON lines, parent and child on one kernel).
  The mesh link would be a separate OS-owned transport that apps reach only through
  `request`.
* **Framing.** Length-prefixed, size-limited, one message type per frame, rejected on
  anything malformed. Chunking for files lives above this, and each file write on the
  receiving side still goes through the guarded path and its password.
* **Throughput.** Multi-gigabit figures depend on the radios and on the encrypted
  channel keeping up; the Python userland makes that doubtful. Not measured.
* **Handoff.** Sender and receiver both name an app. The receiver's OS validates the
  payload against that app's declared schema and delivers it as a command. Unknown
  fields are dropped, oversized payloads refused, control characters stripped, like
  any other app message. "Instantly re-rendering the exact user state" is the app's
  job, never the OS's.

## 4. Resource sharing

This is where the sketch is most dangerous, so the rules are strict.

* **Remote camera.** A request, `mesh.camera`, with the `system` permission, a
  permit, and the password in the OS's own prompt, **per session**. The OS draws a
  camera-in-use indicator in the trusted overlay that an app cannot cover or
  suppress. No standing grant. A paired phone silently becoming a webcam is a
  surveillance feature; I will not design it without the indicator and the prompt.
* **Cellular tunnel.** Allowed to be a standing grant, because rule 3 lets a grant be
  permanent if the password is typed to make it. Conditions: made with the password on
  the machine that owns the modem; scoped to named peers; every use audited on both
  machines; the traffic is still ordinary outbound connections, so each app still
  needs its firewall rule and its encryption rules (no plain `http://`). "Without the
  user ever interacting" is satisfied by the standing grant, not by skipping
  authorisation. Carrier terms and data cost land on the owner, so the grant screen
  must say so.
* **Both ends authorise.** A request from a paired peer does not authorise itself. The
  receiving machine checks its own pairing record and capability list and writes its
  own audit entry. A compromised laptop must not be able to turn on the phone's
  camera.

## Proposed surface (none of it exists)

| Name | What | Rule |
|---|---|---|
| `ACTIONS`: `mesh.pair`, `mesh.unpair`, `mesh.link`, `mesh.camera`, `mesh.tether`, `mesh.handoff` | One password-checked action each | 1 |
| `request` actions with the same names | App-facing entry, `system` permission plus permit | 2 |
| Firewall rule shape `peer:<key id>`, port, protocol | A link is a firewall rule | 3 |
| Peer transport | Encrypted, authenticated, OS-owned | 4, 5 |
| Schemas and hostile-input tests for every message | Size limit, unknown fields dropped, control characters stripped | 1, command protocol |

## Phases

Each phase ships only when its tests pass, including refusal tests. Phase 0 is this file.

1. **Pairing and identity**, no radio: pairing record store, key sealing, `mesh.pair` /
   `mesh.unpair`, audit entries. Testable here with a loopback peer.
2. **Link over an ordinary network** (loopback or LAN), encrypted, behind a firewall
   rule. Proves the handshake and framing without any radio-specific hardware.
3. **Handoff** over that link, app-to-app, schema-checked.
4. **Proximity** (Bluetooth beacon, then UWB). Needs real hardware and the firmware
   decision.
5. **Camera and tether.** Last, because they depend on everything above plus the
   overlay indicator.

## Decisions the owner has to make

1. **Add a vetted crypto dependency** for a Noise-style handshake and AEAD? KOS has
   none today. Without it, phases 2 to 5 cannot be built honestly.
2. **Firmware gate.** Accept `kos.firmware=warn` on mesh machines, or keep radios
   unbound and the mesh off? There is no third option: the sketch needs the chips KOS
   currently powers down.
3. **Central account.** Confirm in-person pairing with no third-party trust root, or
   decide an account is wanted anyway.
4. **KOS-to-KOS only,** or also non-KOS peers treated as remote, untrusted parties.

## What this does not cover

Radio support, UWB, proximity, app-state handoff, camera and tether: none of it exists, and nothing
about it has been run. Claims about Linux UWB and Bluetooth support are unverified. Pairing, the link and sync
exist (see the status paragraph at the top) but were only run on one Linux machine over loopback.
