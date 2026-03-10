# Tinkering: bpf_throw + RCU/preempt lock leak from subprogs — 2026-03-10

## Question
Does the verifier correctly reject bpf_throw from a static subprog when RCU or preempt locks are held?

## Hypothesis
The verifier will NOT reject it because `check_resource_leak()` uses `check_lock=!curframe`, which is false for subprogs. Exception exits from subprogs skip lock validation.

## Method
1. Analyzed `process_bpf_exit_full()` (verifier.c:20957): exception exit calls `check_resource_leak(env, true, !curframe, ...)`. When curframe > 0, check_lock=false, so active_rcu_locks, active_preempt_locks, and active_irq_id are NOT checked.
2. Wrote 4 test BPF programs and loaded them via `bpftool prog load` on host kernel (6.13.2):
   - Test 1 (baseline): bpf_throw + RCU in main prog → **REJECTED** (correct)
   - Test 2: Main acquires RCU lock, calls always-throwing subprog → **LOADED** (bug!)
   - Test 3: Subprog acquires RCU lock and throws → **LOADED** (bug!)
   - Test 4: Main acquires preempt_disable, calls always-throwing subprog → **LOADED** (bug!)

## Results
**Safety bug confirmed.** Three test cases that should be rejected passed verification:
- bpf_rcu_read_lock leaked via exception from subprog (2 scenarios)
- bpf_preempt_disable leaked via exception from subprog

At runtime, bpf_throw unwinds the stack via ORC without releasing user-acquired locks. This causes:
- RCU read lock never released → potential RCU stalls
- Preempt counter imbalance → scheduling anomalies
- IRQ save state leaked → interrupt handling corruption

## Root Cause
`process_bpf_exit_full()` at line 20957 passes `check_lock=!env->cur_state->curframe`. For normal exits from subprogs, check_lock=false is correct because locks propagate to the caller and are checked at the main program exit. But exception exits (line 20972) return immediately via `PROCESS_BPF_EXIT` without unwinding through intermediate frames, so locks are never checked.

The spin_lock case is NOT affected because spin locks are checked at the call site (line 21172: "function calls are not allowed while holding a lock") before bpf_throw even runs.

## Fix
One-line change in `process_bpf_exit_full()`:
```c
// Before:
int err = check_resource_leak(env, exception_exit,
                              !env->cur_state->curframe,
                              "BPF_EXIT instruction in main prog");
// After:
int err = check_resource_leak(env, exception_exit,
                              exception_exit || !env->cur_state->curframe,
                              exception_exit ? "bpf_throw" :
                              "BPF_EXIT instruction in main prog");
```

## Conclusions
The verifier's lock checking has a gap for exception exits from subprogs affecting: bpf_rcu_read_lock, bpf_preempt_disable, bpf_local_irq_save. The existing test in exceptions_fail.c (`reject_subprog_with_rcu_read_lock`) doesn't catch this because its subprog has a conditional throw, so the normal return path (which IS checked) provides coverage. A subprog that ALWAYS throws, or one that acquires and leaks a lock on the exception path only, escapes verification.
