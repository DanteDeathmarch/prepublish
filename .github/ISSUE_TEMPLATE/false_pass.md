---
name: It passed when it should have failed
about: The tool said everything was fine and it wasn't
title: 'FALSE PASS: '
labels: bug, false-pass, priority
assignees: ''
---

**This is the most important kind of report for these tools.** They exist to catch
things; one that quietly misses is worse than one that doesn't exist, because it gets
trusted.

**What did you run?**

```
```

**What did it report?**

```
```

**What was actually wrong that it missed?**
<!-- The file, the secret, the unpushed commit, the dead key — whatever it should have
     caught. Redact any real credential; describe its shape instead (e.g. "a 40-char
     hex string assigned to API_KEY"). -->

**Can you reproduce it with a fake/safe example?**
<!-- Hugely helpful, and it lets the fix ship with a test. Never paste a real secret. -->

```
```

**Environment**

- OS:
- Python version:
- Tool version:
