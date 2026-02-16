from typing import Any, Dict, List, Tuple
from collections import defaultdict, deque

def simulate_trace(plan: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[int, int]]:
    """
    Return:
      - trace_steps: augmented steps with virtual fork/join nodes
      - lane_map: step_id -> lane index (for parallel branches)
    """
    # Build deps graph
    deps = {int(s["step_id"]): list(s.get("dependencies", []) or []) for s in plan}
    children = defaultdict(list)
    indeg = defaultdict(int)
    for sid, ds in deps.items():
        indeg[sid] = len(ds)
        for d in ds:
            children[int(d)].append(sid)

    # Identify "fan-out" roots: nodes with multiple children
    fanout = [n for n, ch in children.items() if len(ch) >= 2]
    fork_of = {}
    join_of = {}

    trace = []
    next_virtual = max(deps.keys() or [0]) + 1

    # Simple heuristic: create fork before first fan-out, and join at the first node that depends on multiple branches
    # (You can refine later; this already fixes "looks linear" problem.)
    fork_id = None
    if fanout:
        fork_id = next_virtual
        next_virtual += 1
        trace.append({"step_id": fork_id, "type": "action", "description": "FORK: start parallel branches", "tool_name": None, "dependencies": []})
        # Rewire: all original roots (deps empty) depend on fork
        for s in plan:
            if not s.get("dependencies"):
                s["dependencies"] = [fork_id]

    # Detect join candidates: nodes with >=2 dependencies
    join_candidates = [s for s in plan if len(s.get("dependencies", []) or []) >= 2]
    if join_candidates:
        join_id = next_virtual
        next_virtual += 1
        # join depends on those deps; and those nodes now depend on join? No — we place join as a virtual node,
        # then make the join_candidate depend on join, and join depend on its original deps.
        jc = join_candidates[0]
        orig_deps = list(jc.get("dependencies", []) or [])
        trace.append({"step_id": join_id, "type": "action", "description": "JOIN: merge parallel branch results", "tool_name": None, "dependencies": orig_deps})
        jc["dependencies"] = [join_id]

    # Lane assignment: each child of the fork gets its own lane; otherwise lane 0
    lane_map: Dict[int, int] = {}
    if fork_id is not None:
        # find immediate children of fork (nodes that depend on fork only)
        fork_children = [s["step_id"] for s in plan if (s.get("dependencies") == [fork_id])]
        for idx, sid in enumerate(sorted(fork_children)):
            lane_map[int(sid)] = idx
        # propagate lane down the branch if single-parent
        changed = True
        while changed:
            changed = False
            for s in plan:
                sid = int(s["step_id"])
                ds = list(s.get("dependencies", []) or [])
                if sid in lane_map:
                    continue
                if len(ds) == 1 and int(ds[0]) in lane_map:
                    lane_map[sid] = lane_map[int(ds[0])]
                    changed = True

    # default lane
    for s in plan:
        lane_map.setdefault(int(s["step_id"]), 0)

    # final trace = virtual nodes + real nodes (keep order by step_id)
    trace_all = trace + plan
    trace_all = sorted(trace_all, key=lambda x: int(x["step_id"]))
    return trace_all, lane_map
