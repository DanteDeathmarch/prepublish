# Contributing

Issues and pull requests are welcome.

**Before opening a PR**

- Keep it dependency-free. The whole point is that this runs anywhere with no install.
- Add a case to the examples in the README if you change behaviour.
- If you change a threshold, say why in the PR — the current numbers are floors chosen
  to catch obviously-broken files, not to be authoritative.

**Reporting a bug**

Include the command you ran, what you expected, and what happened. If a file was
misjudged, say which verdict you expected and why — false PASSes are more serious than
false FAILs here.
