# Survey: LiveTalking

Clone: `refs/LiveTalking` (paths below are relative to it).
Legend: **CONFIRMED** = read in the clone. **INFERRED** = derived, not stated in the repo.

## Identity

| Field | Value | Evidence |
|---|---|---|
| Clone remote | `https://github.com/AiBot-Tools/LiveTalking` (operator's fork) | `git remote -v` CONFIRMED |
| Upstream | `https://github.com/lipku/LiveTalking` (author Hengzhong Li, `lipku`) | `README-EN.md` citation block, file headers `avatars/base_avatar.py:2` CONFIRMED |
| License | Apache-2.0 | `LICENSE` CONFIRMED. Note: README section 8 adds a non-license "statement" that published videos must carry the LiveTalking watermark/logo, and `avatars/base_avatar.py:449` burns a "LiveTalking" `cv2.putText` watermark into every frame. Also a paid "Commercial Version" exists (`README-EN.md` section 7). |
| Commit | `b3e7490a20e7a6330492f8a6ea8200a5d50279d1` 2026-09-13 ("feat: update README with commercial version") | `git log -1` CONFIRMED |
| Stack | Python 3.10+, PyTorch (README tested on 2.9.1/CUDA 12.8), aiohttp + aiortc (WebRTC), `av`, OpenCV, edge_tts, openai SDK, dashscope, transformers/diffusers (MuseTalk) | `requirements.txt`, `README-EN.md` CONFIRMED |
| Tests | One unit test file, `tests/test_asr_server.py` (mocks torch/aiohttp/funasr) | CONFIRMED |
| Dockerfile | Stale NVIDIA CUDA 11.6 / torch 1.12 image that references a `nerfstream` path that no longer exists | `Dockerfile` CONFIRMED |

## What it is

A real-time "digital human" streaming server: text or audio in, lip-synced avatar video + audio out over WebRTC (offer/WHEP), RTMP, or a virtual camera. Pipeline (CONFIRMED in `README-EN.md` "Core Flow" and the code): `/human` text -> optional LLM (`llm.py`, OpenAI-compatible, streamed and split on punctuation) -> TTS plugin (`tts/*.py`) producing 16 kHz PCM in 20 ms chunks tagged with `{'status':'start'|'end','text':...}` event points -> audio-feature extractor (`avatars/audio_features/{mel,whisper,hubert}.py`) -> lip-sync model batch inference (`avatars/{wav2lip,musetalk,ultralight}_avatar.py`) -> paste mouth region back onto pre-extracted full-body frames -> `streamout/*` output. Idle state cycles pre-rendered frames (no GPU) and can play "action choreography" custom videos (`set_audiotype`). Supports interrupt (`flush_talk`), server-side recording via ffmpeg (`/record`, `GET /record/{sessionid}`), multi-session concurrency with a cap, and an avatar-generation task API that turns an uploaded video into an avatar (`server/task_manager.py`).

It is **not** an agent framework. There is no planner, no tool calling, no memory, no roles. It is a media rendering appliance that an agent could drive over HTTP.

## Orchestration model

None in the agentic sense. CONFIRMED:
- `server/session_manager.py`: singleton `SessionManager` with `max_session` cap, `create_session()` builds a `BaseAvatar` in a thread pool (model load is slow), `remove_session()` sets `quit_event` to cascade-stop render/inference/TTS threads.
- `avatars/base_avatar.py:render()`: per-session thread trio: `tts.render` (text->PCM), `inference` (features->frames, batched `batch_size` frames), `process_frames` (paste-back + push). Backpressure: `render()` sleeps when `output.get_buffer_size() >= 5`.
- `server/task_manager.py`: `ThreadPoolExecutor(max_workers=1)` job queue for avatar generation with `pending/running/completed/failed` states, progress 0-100, optional webhook `notify_url`.
- `llm.py`: single synchronous streamed chat completion; hard-coded Chinese system prompt ("you are a knowledge assistant, be brief and colloquial"); sentence chunks >10 chars are pushed to TTS as they arrive (time-to-first-audio optimization).

## Agent roster / roles found

None. No agent definitions, roles, personas, or delegation exist anywhere. The only "role" is the hard-coded system prompt string in `llm.py:59`. (CONFIRMED by full file listing and grep.)

## Memory model

None. `llm_response()` sends a single user message with no history (`llm.py:58-60`). Session state is in-process only (`SessionManager.sessions` dict, `TaskManager.tasks` dict); nothing persists across restart except recorded MP4s under `data/record/` and generated avatars under `data/avatars/`. CONFIRMED.

## Tool / plugin / MCP model

- No MCP, no tools. CONFIRMED.
- Plugin registry: `registry.py` is a ~50-line decorator registry keyed by category (`stt`, `llm`, `tts`, `avatar`, `output`/`streamout`) and name; `registry.create(category, name, **kwargs)` instantiates. Plugins register via `@register("tts","edgetts")` etc. (`tts/edge.py:13`, `streamout/virtualcam.py:15`, `avatars/wav2lip_avatar.py:87`). CONFIRMED.
- Base contracts: `tts/base_tts.py` (`txt_to_audio(msg)` pushes 20 ms frames to parent with event points; `flush_talk()` clears queue and sets PAUSE), `streamout/base_output.py` (`start/push_video_frame/push_audio_frame/get_buffer_size/stop`), `avatars/base_avatar.py` (`inference_batch`, `paste_back_frame`). CONFIRMED.
- Modules are loaded lazily by string map (`base_avatar.py:75-107`, `app.py:107-113`), not by entry points.
- LLM provider table `llm.py:LLM_PROVIDERS` (dashscope, orcarouter) uses env var names for keys; TTS plugins read `DASHSCOPE_API_KEY`, `DOUBAO_API_KEY`, Tencent secrets, Azure keys from env (`.env.example`). CONFIRMED.

## Sandbox and security posture

CONFIRMED, all negative for our purposes:
- Binds `0.0.0.0:<listenport>` (`app.py:184`); README says open TCP 8010 and UDP 1-65535.
- **No authentication on any route** (grep for `Authorization|bearer|token` finds only outbound TTS auth headers). Admin endpoints `GET /api/admin/config` (dumps `vars(opt)` including `TTS_SERVER`, `push_url`) and `/api/admin/sessions` are open (`server/routes.py:176-215`).
- CORS `*` with `allow_credentials=True` on every route (`app.py:160-169`).
- `POST /api/avatar/task` accepts an arbitrary local `video_path` and an arbitrary `notifyurl` the server will POST to (`server/avatar_routes.py:56-99`, `server/task_manager.py:123-133`): file-read and SSRF primitives for any network peer.
- `custom_config` in the WebRTC offer body is client-supplied JSON whose `imgpath`/`audiopath` are globbed/read from the server filesystem (`app.py:86-88`, `base_avatar.py:__loadcustom`).
- `stop_recording()` builds an ffmpeg command line with `os.system()` string formatting on `sessionid` (`base_avatar.py:284-286`); WHEP lets the client choose `sessionid` via query (`rtc_manager.py:113`). Path segment routing limits the traversal, but it is shell string interpolation of client input.
- Secrets: read from env / `.env` via `python-dotenv` (`app.py:222`); no vault, no redaction in logs (`llm.py` logs the full user message and every LLM chunk at INFO).
- No sandboxing, no human-in-the-loop, no rate limits beyond `max_session`, no audit log. The Dockerfile is stale and unrunnable as written.

## BEST PARTS

1. **Text-to-avatar as a stateless HTTP appliance with `echo` vs `chat` modes** (`server/routes.py:human`, `docs/api.md` section 3). Sector: growth (sales/social presenter), ops. Why: `type: "echo"` makes the engine a pure renderer: the *kernel's* router produces the script, logs `llm.request/llm.response`, and the engine only voices it. This is exactly the split invariant 2/4 needs: LiveTalking's own `chat` mode (which calls the LLM itself) is disabled and the presenter agent only ever uses `echo`.

2. **Sentence-streaming to TTS for time-to-first-audio** (`llm.py:64-77`): split the token stream on punctuation, flush chunks >10 chars to TTS immediately. Sector: growth. Why: this is the latency trick that makes a live presenter feel responsive; the kernel can do the same split on the router's stream before calling the engine's `/human` echo endpoint.

3. **Event points riding on audio frames + SSE** (`tts/base_tts.py`, `tts/edge.py:29-36`, `base_avatar.py:notify`, `server/routes.py:sse_handler`). Each 20 ms frame carries `{'status':'start'|'end','text':...}` plus caller-supplied `datainfo`; `notify()` fans them out to SSE subscribers. Sector: growth, ops-security. Why: gives the kernel per-utterance start/end acks it can log as events (`presenter.utterance.start/end` with the text and an opaque run/goal id in `datainfo`), so the event log can prove what the avatar actually said.

4. **Interrupt / flush semantics** (`BaseTTS.flush_talk`, `BaseAvatar.flush_talk`, `/interrupt_talk`, `interrupt: true` on `/human`). Sector: growth, ops-security. Why: a hard "stop talking now" that clears queued text and pauses the TTS state machine is the kill-switch a human approver needs during a live sales session.

5. **Idle choreography: pre-rendered frame cycles when silent, "action" clips by `audiotype`** (`base_avatar.py:__loadcustom`, `set_custom_state`, `process_frames`; `/set_audiotype`). Sector: growth. Why: zero-GPU idle loop and named actions ("wave", "point at product") are how a 24/7 unattended presenter stays cheap and natural; the kernel can bind action names to allowed values in a manifest rather than letting the model send free-form config.

6. **Output as a swappable transport: WebRTC (offer + standards-based WHEP), RTMP push, virtual camera** (`streamout/*.py`, `server/rtc_manager.py:handle_whep`, `docs/virtualcam_guide.md`). Sector: growth. Why: the same rendered stream can go to a browser preview for human review (WebRTC), to a platform (RTMP to YouTube/Bilibili), or into Zoom/Teams via OBS Virtual Camera for a live sales call. Choose the transport per agent tier: preview-only for tainted runs, RTMP only after approval.

7. **Server-side recording and batch short-video mode** (`/record` start/end, `GET /record/{sessionid}`, README "Batch Short Video Creation"). Sector: growth (producer/publisher). Why: a non-live path: script -> `echo` -> record -> MP4 artifact -> review queue -> publisher. This fits Phase 4's "clip -> scheduled post with a human approval in between" exactly, and never needs a live socket to a platform.

8. **Tiny decorator plugin registry with three base contracts** (`registry.py`, `tts/base_tts.py`, `streamout/base_output.py`, `avatars/base_avatar.py`). Sector: engineering. Why: the TTS/output/avatar seams are the right shape for a pack manifest: each plugin is a name + a small ABC. We would express the same seams as MCP servers or kernel-side adapters, not import-time registration.

## BAD PARTS / anti-patterns

1. **Zero auth, 0.0.0.0 bind, wildcard CORS with credentials** (`app.py:160-169,184`; no auth anywhere). Why out: violates invariant 1 outright. If we host it, it runs inside a T2/T3 container on the internal network and only the kernel's egress proxy or a kernel-side adapter can reach it.

2. **Client-controlled local paths and callback URLs** (`server/avatar_routes.py` `video_path`, `notifyurl`; `custom_config.imgpath/audiopath`; `os.system` in `base_avatar.py:286`). Why out: arbitrary file read, SSRF, and shell interpolation from network input. The kernel never exposes these routes to an agent; avatar generation is a kernel-only, human-approved job with a fixed mount root.

3. **The engine calls the LLM itself with keys in env and a hard-coded persona** (`llm.py`, `.env.example`). Why out: bypasses router, budgets, taint, and the two-event LLM log (invariant 2 and 4). We disable `chat` mode and never give the container a provider key.

4. **Secrets and full prompts logged at INFO, no redaction** (`llm.py:52,66`, `utils/logger.py`). Why out: our event log is redacted and chained; the engine's stdout must be treated as untrusted output, captured and redacted by the kernel, never trusted as the record.

5. **Watermark burned into every frame and a non-license publication "statement"** (`base_avatar.py:449`, `README-EN.md` section 8), plus a paid commercial tier holding the "enhancement" features. Why out: Apache-2.0 permits removal, but a sales/social presenter with a competitor's logo on it is unusable; we must patch the frame stamp out and accept that the open-source model set is the floor, not the product.

6. **No persistence, no tests to speak of, stale Dockerfile, CUDA-only paths** (`SessionManager`/`TaskManager` in-memory; one test; `Dockerfile`; `avatars/ultralight_avatar.py:169` hard-codes `.cuda()`). Why out: we cannot rely on its restart safety or its container image; we build our own image and treat the engine as replaceable.

## Hardware needs on the operator's M1 Max (64 GB, macOS 15.6)

- Device selection: `utils/device.py` returns `cuda` -> `mps` -> `cpu`; `wav2lip_avatar.py` and `musetalk_avatar.py` use it (MuseTalk moves VAE/UNet to `.half()` on that device). **Ultralight is CUDA-only** (`.cuda()` hard-coded). Local ASR (`server/asr_server.py`) is CUDA-or-CPU, no MPS. CONFIRMED.
- Published FPS numbers are NVIDIA only (wav2lip256: 60 fps on RTX 3060; musetalk: 42 fps on 3080Ti); the real-time bar is `inferfps >= 25` (`README-EN.md` section 6). **INFERRED**: wav2lip256 (a small conv net, batch 16, 256 px crops) should clear 25 fps on MPS on an M1 Max; MuseTalk (VAE + UNet per frame, fp16) is likely below real time on MPS and is better used in the recorded, non-live path. Must be measured with `--model wav2lip` and the `actual avg infer fps` log line before any live use.
- Memory: wav2lip weights are small; MuseTalk needs sd-vae + UNet + Whisper features (INFERRED: low single-digit GB). Both fit comfortably under the ~40 GB local-model budget alongside a Bonsai llama.cpp instance. CPU is the other axis: each session's H.264/VP8 encode runs on CPU (README section 6).
- Docker on Colima cannot see the GPU, so the engine must run **natively** on macOS for MPS, like Ollama. That conflicts with invariant 9's container story; the resolution is: the engine is an operator-installed native service on loopback, reachable only from the kernel (adapter), and the *agent* that drives it runs in the normal sandbox with a single scoped MCP tool.
- Virtual camera on macOS needs OBS Studio installed once (`docs/virtualcam_guide.md`; pyvirtualcam); RTMP needs `python_rtmpstream` which is not in `requirements.txt`; recording needs `ffmpeg` on PATH. TTS defaults to EdgeTTS (network call to Microsoft), so a fully local presenter needs a local TTS plugin (GPT-SoVITS/CosyVoice are supported via `TTS_SERVER`).

## Conflicts with CLAUDE.md invariants

1. Invariant 1 (loopback + bearer): binds `0.0.0.0`, no auth, CORS `*`. Must be fronted/rebound by the kernel and never exposed to agents directly.
2. Invariant 2 (agents never hold keys): the engine reads provider/TTS keys from env and calls LLM/TTS providers itself. Disable `chat`; inject TTS credentials at the egress proxy or run local TTS; the agent gets only an MCP tool, never the engine's port.
3. Invariant 3 (gate on every tool call; irreversible needs a human): RTMP push / virtual camera into a live call is irreversible speech to real people; classify `presenter.go_live`, `presenter.push_rtmp` as `irreversible`; `presenter.say` (echo) as `write`; `presenter.preview`, `presenter.is_speaking`, `presenter.status` as `read`. Tainted runs (Telegram/SMS-originated) cannot call `say` without a human.
4. Invariant 4 (two-event LLM log): the engine's built-in LLM path bypasses it. Only the router speaks; the engine echoes.
5. Invariant 5 (redacted, chained log): engine logs are not the record; the kernel logs `presenter.*` events from SSE acks with `MAX_LOGGED_OUTPUT` respected.
6. Invariant 7 (unknown tools kernel-only): `/api/avatar/task`, `/api/admin/*`, `/record` download, and `set_audiotype` with free-form config stay `kernel-only`; only a fixed enum of action names is exposed.
7. Invariant 9 (container hardening): the engine needs Metal, so it runs natively; that is a documented exception like Ollama, not a weakening. The driving agent stays in T1/T2.

## Verdict

Take the pipeline shape and the wire contract: text `echo` in, 20 ms audio frames with start/end event points and SSE acks out, hard interrupt, idle choreography by named action, swappable transport (WebRTC preview, RTMP, virtual camera), and server-side recording for a review-then-publish path, driven by the kernel's router and logged as `presenter.*` events. Leave the engine's own LLM/TTS credential handling, its unauthenticated 0.0.0.0 API with file-path/callback-URL parameters, its logging, its burned-in watermark, and any notion that it is an orchestration layer. Treat LiveTalking as a candidate native, loopback-only "presenter engine" behind a single kernel-side MCP adapter, validated first by an MPS FPS measurement with wav2lip256 on the M1 Max.
