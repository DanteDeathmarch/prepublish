---
name: Bug report
about: Something behaved differently than it said it would
title: ''
labels: bug
assignees: ''
---

**What did you run?**
<!-- The exact command. Paste it. -->

```
```

**What did it say?**
<!-- Paste the full output, including the exit code: `echo $?` on the next line. -->

```
```

**What should it have said?**

**Which of these is it?**

- [ ] **It passed when it should have failed** ← most serious, please say so loudly
- [ ] It failed when it should have passed (false positive)
- [ ] It crashed
- [ ] The output was confusing or wrong in some other way

**Environment**

- OS:
- Python version (`python --version`):
- Tool version (`--version`):

---

*A tool that reports success when it shouldn't is worse than no tool, because it gets
trusted. If you found one of those, it goes to the front of the queue.*
