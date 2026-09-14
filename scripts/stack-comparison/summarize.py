#!/usr/bin/env python3
"""Join measured stack counts and generate the paper's PGFPlots figure."""

import argparse
import csv
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_csv(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def coords(rows, x, y):
    return " ".join(f"({r[x]:.12g},{r[y]:.12g})" for r in rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--inputs", type=Path, required=True)
    ap.add_argument("--binius", type=Path, required=True)
    ap.add_argument("--zekra", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    manifest = json.loads((args.inputs / "manifest.json").read_text())
    bmeta = json.loads((args.binius / "metadata.json").read_text())
    zmeta = json.loads((args.zekra / "measurement.json").read_text())
    arith = json.loads((args.zekra / "arithmetic-verification.json").read_text())
    binius = {r["case_id"]: r for r in read_csv(args.binius / "measurements.csv")}
    zekra = {}
    for row in read_csv(args.zekra / "constraints.csv"):
        key = row["case_id"]
        if key in zekra:
            assert all(row[k] == zekra[key][k] for k in row if k != "family")
        zekra[key] = row
    zcases = {r["case_id"]: r for r in zmeta["cases"]}
    verified = {r["case_id"]: r for r in arith["cases"]}
    assert bmeta["all_constraints_verified"] and bmeta["all_requested_proofs_verified"]
    assert bmeta["input_manifest_sha256"] == sha(args.inputs / "manifest.json")
    assert bmeta["measurements_sha256"] == sha(args.binius / "measurements.csv")
    assert zmeta["status"] == "complete"
    assert len(manifest["cases"]) == 21
    joined = []
    for case in manifest["cases"]:
        key = case["case_id"]
        b, z, zm, av = binius[key], zekra[key], zcases[key], verified[key]
        assert b["witness_check_success"].lower() == "true"
        assert z["witness_satisfied"].lower() == "true" and av["satisfied"]
        for column in ("L", "call_count", "ret_count", "jmp_count"):
            assert int(b[column]) == int(z[column]) == case[column], (key, column)
        assert int(b["D"]) == int(z["D"]) == case["actual_depth"]
        assert int(b["actual_depth"]) == int(z["actual_max_depth"]) == case["actual_depth"]
        assert zm["events_sha256"] == case["sha256"]["events.tsv"]
        assert sha(args.inputs / key / "events.tsv") == zm["events_sha256"]
        assert av["r1cs_constraints"] == int(z["r1cs_constraints"])
        kinds = ("and_constraints", "imul_constraints", "bmul_constraints", "zero_constraints")
        assert sum(int(b["delta_" + k]) for k in kinds) == int(b["delta_native_constraint_count"])
        for k in (*kinds, "native_constraint_count"):
            assert int(b["with_" + k]) - int(b["without_" + k]) == int(b["delta_" + k])
        for family in case["families"]:
            joined.append(dict(
                family=family, case_id=key, L=case["L"], D=case["actual_depth"],
                call_count=case["call_count"], ret_count=case["ret_count"], jmp_count=case["jmp_count"],
                binius_native=int(b["delta_native_constraint_count"]),
                binius_and=int(b["delta_and_constraints"]), binius_imul=int(b["delta_imul_constraints"]),
                binius_bmul=int(b["delta_bmul_constraints"]), binius_zero=int(b["delta_zero_constraints"]),
                zekra_r1cs=int(z["r1cs_constraints"]), zekra_memory_mode={"1": "network", "2": "linear"}[z["smart_memory_mode"]],
                zekra_pointer_bits=int(z["stack_pointer_bits"]), binius_pointer_bits=15,
                events_sha256=zm["events_sha256"], witness_checks_pass=True,
            ))
    args.output.mkdir(parents=True, exist_ok=True)
    with (args.output / "constraints.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(joined[0]))
        writer.writeheader()
        writer.writerows(joined)
    groups = {f: sorted([r for r in joined if r["family"] == f], key=lambda r: (r["L"], r["D"]))
              for f in ("length", "depth", "diagonal")}
    assert [len(groups[f]) for f in groups] == [7, 9, 7]
    for r in joined:
        assert r["binius_native"] == 14 * r["L"] + 913
    for r in groups["length"]:
        assert r["zekra_r1cs"] == 83 * r["L"] - 87
    diagonal = [dict(r, bnorm=r["binius_native"] / groups["diagonal"][0]["binius_native"],
                     znorm=r["zekra_r1cs"] / groups["diagonal"][0]["zekra_r1cs"],
                     reference=(r["L"] / 64) ** 1.5) for r in groups["diagonal"]]
    plot = r"""% Generated from independently compiled counts; see provenance.json.
\begin{tikzpicture}
\begin{groupplot}[
  group style={group size=3 by 1,horizontal sep=0.70cm},
  width=0.31\textwidth,height=3.72cm,
  xmode=log,log basis x=2,ymode=log,
  tick label style={font=\scriptsize},label style={font=\footnotesize},
  title style={font=\footnotesize},axis line style={gray!65},
  grid=major,grid style={gray!18},/tikz/mark size=1.6pt,
  legend style={font=\footnotesize,draw=none,legend columns=3,
    at={(1.72,1.30)},anchor=south},
]
\nextgroupplot[title={(a) Fixed $D=8$},xlabel={EP capacity $L$},
  ylabel={Native constraints},xtick={64,256,1024,4096},
  xticklabels={64,256,1024,4096},xmin=52,xmax=5000,
  ymin=1000,ymax=500000,ytick={1000,10000,100000}]
"""
    styles = {"z": "black!75,dashed,thick,mark=square*", "b": "blue!75!black,solid,thick,mark=*"}
    def line(rows, x, y, style):
        return f"\\addplot[{style}] coordinates {{{coords(rows, x, y)}}};\n"
    plot += line(groups["length"], "L", "zekra_r1cs", styles["z"])
    plot += line(groups["length"], "L", "binius_native", styles["b"])
    plot += r"\addlegendimage{gray!80,densely dotted,thick}" + "\n"
    plot += r"\legend{ZEKRA C6 (R1CS),zkCFA64 stack (word),$L\sqrt{D}$ reference}" + "\n"
    plot += r"""\nextgroupplot[title={(b) Fixed $L=1024$},xlabel={Stack depth $D$},
  xtick={1,4,16,64,256},xticklabels={1,4,16,64,256},xmin=0.7,xmax=350,
  ymin=10000,ymax=500000,ytick={10000,100000}]
"""
    plot += line(groups["depth"], "D", "zekra_r1cs", styles["z"])
    plot += line(groups["depth"], "D", "binius_native", styles["b"])
    plot += r"""\nextgroupplot[title={(c) $D=L/4$ (normalized)},xlabel={EP capacity $L$},
  xtick={64,256,1024,4096},ytick={1,10,100},ymin=0.8,ymax=700,
  xticklabels={64,256,1024,4096},xmin=52,xmax=5000]
"""
    plot += line(diagonal, "L", "znorm", styles["z"])
    plot += line(diagonal, "L", "bnorm", styles["b"])
    plot += line(diagonal, "L", "reference", "gray!80,densely dotted,thick")
    plot += "\\end{groupplot}\n\\end{tikzpicture}\n"
    (args.output / "plot.tex").write_text(plot)
    (args.output / "figure.tex").write_text(r"""\begin{figure*}[t]
  \centering
  \input{stack-evaluation/plot.tex}
  \caption{Stack-checking constraint growth.}
  \label{fig:stack-constraints}
\end{figure*}
""")
    provenance = dict(
        source_paths={"inputs": str(args.inputs.resolve()), "binius": str(args.binius.resolve()), "zekra": str(args.zekra.resolve())},
        source_sha256={"inputs_manifest": sha(args.inputs / "manifest.json"),
                       "binius_measurements": sha(args.binius / "measurements.csv"),
                       "zekra_measurements": sha(args.zekra / "constraints.csv"),
                       "zekra_arithmetic_verification": sha(args.zekra / "arithmetic-verification.json")},
        unique_cases=21, plotted_points_per_backend=23,
        binius_unit="incremental native AND+IMUL+BMUL+ZERO constraints from enabling RawShadow",
        zekra_unit="BN254 R1CS rows for the released C6 component",
        fitted_identities={"binius_measured": "14*L+913", "zekra_fixed_D8_measured": "83*L-87"},
        normalized_reference="(L/64)^1.5 when D=L/4; theoretical reference only, not measured constraints",
        caveat="Backend-native counts are not equal-cost operations or a proving-time speedup.",
        measurements_sha256=sha(args.output / "constraints.csv"),
    )
    (args.output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(json.dumps({"cases": 21, "binius_depth_scan": [r["binius_native"] for r in groups["depth"]],
                      "zekra_depth_scan": [r["zekra_r1cs"] for r in groups["depth"]],
                      "diagonal_growth": {"binius": diagonal[-1]["bnorm"], "zekra": diagonal[-1]["znorm"], "reference": 512}}, indent=2))


if __name__ == "__main__":
    main()
