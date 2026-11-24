"""LangGraph orchestration of the Guardian pipeline.

Package map:
    state.py     GraphState (checkpointed, JSON-only) and RunContext (live objects, registered per run id)
    workflow.py  node wiring and routing functions (the supervisor), run() / resume() / resume_batch() drivers,
                 and the end-of-run files (graph.json, run_summary.json)

The agents themselves (the graph's nodes) live in guardian/agents/.
"""