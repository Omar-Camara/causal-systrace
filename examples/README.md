# Demo artifacts (pipeline sample)

Committed files you can zip or link for a report:

| File | Description |
|------|-------------|
| `demo_enriched.csv` | Synthetic enriched trace (120 rows, **25** unique `channel` values). |
| `demo_graph.dot` | Graphviz output from `causal.py` (`--window-ms 0.5 --threshold 0.35`). |
| `demo_graph.png` | Rendered image (regenerate with `dot` if missing). |
| `build_demo_artifacts.py` | Regenerates both files: `python3 examples/build_demo_artifacts.py` |

Render the graph:

```bash
dot -Tpng examples/demo_graph.dot -o examples/demo_graph.png
```

**Real traces** (your Lima runs): `causal.py` reported **25 channels** for `enriched_tmp.csv` (~374 events, ~10 s); a **20-row** toy trace had **~8–9** distinct channels in the top summary.
