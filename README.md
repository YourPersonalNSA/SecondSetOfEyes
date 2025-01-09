## Second Set of Eyes V1
---
A lifelogging and personal analytics project that captures:
- Invocations of binaries
- Filesystem writes
- Browser tabs

While one could write about what they did today, we are too lazy and we would like a system that could infer our intent over time without spelling it out. Today's AIs, that is, LLMs, should be able to assist with this given scaffolding that affords them visibility into our activities, a way to know the days of our life, a way to see what we can see.

Pixels on screen could be offered to modern multimodal LLMs in a very direct interpretation of "see" but this can hardly be [reliable](https://xcancel.com/zetalyrae/status/1876393261683834991#m) or effective in terms of compute power.

State of memory defines the pixels we see on screen. It stores the bitmaps and the strings that made them. Be it volatile or non-volatile, state of memory is the ultimate side effect of any user intent in a computer interaction. However, bytes in memory offer a very low level and scattered representation of user intent, one that cannot be easily interpreted by AI models. At least, not yet.

Truthfully, one could inspect state of memory in a constrained manner and glean high level representation of intent by looking at specific files that contain e.g. shell command history or by traversing the filesystem to record a snapshot of all modification dates. This tells little about activity over time unless referenced to a snapshot made earlier.

Instead of resorting to polling and comparisons of snapshots, one should focus on directly observing [events](https://gwern.net/nenex) that shape the state of memory.

Below is the list of what we have established as viable event sources. Some are downstream of others.

Some events are system-wide:

|Event|Tool|
|---|---|
|[Keystrokes](https://writings.stephenwolfram.com/2012/03/the-personal-analytics-of-my-life/) and mouse movement|evtest, pyevdev|
|Filesystem modifications|watchmedo, pyfanotify|
|Network traffic|wireshark, mitmproxy|
|Process start|forkstat, pyroute2|
|Syscalls|auditd|

Some events are application specific:

|Event|Tool|
|---|---|
|Browser requests|A WebExtension|
|Browser tabs|A WebExtension|

After some careful consideration we have decided that:
- Invoked binaries
- Visited URLs
- Edited files

Are the three side effects of one's interactions with the computer that should not be too complex to parse for today's AIs while also being information rich.

TODO: Add samples
