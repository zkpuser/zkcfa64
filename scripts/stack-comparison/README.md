# Cross-backend stack constraint comparison

The experiment compares the compiled contribution of Binius64's production
timestamped stack checker with ZEKRA's released C6 shadow-stack component.
Both consume the same 21 balanced synthetic event sequences. Measurements are
compiler output, not values generated from an asymptotic expression.

## Reproduce the measurements

Use the Binius [campaign instructions](../../zkcfa-binius64/research/results/timestamped-stack/README.md)
to build the research example, generate fresh shared inputs, and measure the
enabled/disabled circuit difference. Use the ZEKRA
[C6 instructions](../../zekra/reproduce/stack_constraints/README.md) on those same
inputs to compile its component and independently verify the exported arithmetic
circuits. Choose new output directories for each campaign.

The Binius research feature does not change the production default. ZEKRA copies
its released component into isolated experiment directories and retains its
push/pop algorithm and the existing native-field memory repair.

## Generate the paper's data and figure

From the repository root, using Python 3:

```sh
python3 scripts/stack-comparison/summarize.py \
  --inputs zkcfa-binius64/research/results/timestamped-stack/inputs \
  --binius zkcfa-binius64/research/results/timestamped-stack/binius \
  --zekra zekra/reproduce/results/timestamped-stack \
  --output output/stack-evaluation
```

The script verifies shared event hashes, operation counts, witness outcomes,
independent ZEKRA arithmetic counts, and all Binius per-type differences. It
outputs the merged CSV, provenance hashes, and PGFPlots sources. Two cases appear
in more than one scan family: 21 unique cases produce 23 points per backend.
Compile the paper with its existing LaTeX workflow to render the vector figure.

## What the plot means

- Panel (a): native stack constraints versus path capacity at depth eight.
- Panel (b): native stack constraints versus depth at capacity 1024. Binius
  keeps its production 15-bit pointer; ZEKRA provisions its stack to the depth
  and uses the released compiler's pointer-width convention. The separate
  fixed-15-bit ZEKRA controls confirm that its depth dependence persists.
- Panel (c): both length and depth increase, with `D=L/4`; each measured series
  is divided by its own `(L,D)=(64,16)` count. The dotted `(L/64)^1.5` line is
  a theoretical `L sqrt(D)` growth reference, not measured ZEKRA constraints.

The released ZEKRA backend chooses linear or network memory checking in these
cases. The plot preserves that measured behavior. R1CS rows and Binius native
word constraints are different size metrics; their ratio is not a proving-time
speedup. This is a structural experiment, with no comparative runtime claim.

The linked experiment instructions describe the controls, component definitions,
and measured count identities. The generated `provenance.json` records the
source paths and hashes used for each comparison.
