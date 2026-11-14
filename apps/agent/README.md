# agent

One app: a **local** AI agent runner. The group has no permissions; the app asks for `service:agent` only.

| program | folder | asks the OS for |
|---|---|---|
| `agent.run` | `run/` | `service:agent` (a model on this computer works on a task inside one folder) |

Set the model first with `kos ai set --url http://127.0.0.1:PORT/... --model NAME`. A remote or https model is
**refused**: local means the bytes do not leave the computer. The agent reaches **one folder** (no `..`, no
symlinks), has no network tool and no code-running tool, and its write tool only *creates* files. Your password
is asked at the moment of use: once to start, once per read tool, and **every time** it wants to write (the prompt
shows the file and size). A no, or three wrong passwords, ends the whole run. Steps, characters and time are budgeted.

A model can be talked into things by a file it reads. That is why the wall is the folder and the password, not the
model's good behaviour. See `kos/agentrun.py`.
