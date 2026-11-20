# SDD ledger — plan: docs/superpowers/plans/2026-10-20-fix-guides.md
Setup: Ruling: no git repo — work in place, no commits, ledger in scratchpad — cost if wrong: no rollback point
Pre-flight: T2 consumes T1 helpers (match); T3 consumes run.py guide (T2); T4 consumes /guide route (T3) + key format (T1) — consistent
Task 1: Ruling: wrote Task 1 and Task 2 tests in one file before either implementation — same RED (module missing) — cost if wrong: none
Task 1: Ruling: extract_json also rejects a non-object JSON — parse_guide needs a dict — cost if wrong: none
Task 1: complete (tests: unittest tests.test_guide tests.test_cveinfo → 20 OK)
Task 2: complete (tests: unittest tests.test_guide tests.test_mitigate → see t12.log)
Task 3: complete (tests: unittest tests.test_web → 10 OK)
