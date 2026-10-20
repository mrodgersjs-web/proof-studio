## What changed

<!-- One or two sentences. Link the issue if there is one. -->

## How it is verified

<!-- Commands and results, pasted. New attack classes need a vector and a scenario row. -->

```
proof-studio run
pytest -q
```

## Checklist

- [ ] `pytest -q` passes locally (no new skips)
- [ ] `proof-studio run` reports ALL EXPECTATIONS MET
- [ ] `ruff check .` is clean
- [ ] New vectors are regenerated with `proof-studio build-vectors` (no hand-edited JSON)
- [ ] README/docs numbers still match the commands that produce them
