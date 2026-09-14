# Source and dependency provenance

The commit IDs below record the component snapshots used to assemble this
repository. Submodule dependencies are recorded separately because they retain
their own histories.

| Component | Source branch | Imported commit |
| --- | --- | --- |
| `zkcfa-binius64` | `optimized` | `8599015f6e1319503329405f74f11b551c9900ba` |
| `zkcfa-binius64/binius64` | submodule pin | `c56e2027591df056cee5bd741085e110d491f28e` |
| `zkcfa-plonk` | `optimized` | `ecd726761d9dfb2f743a8f1ba804774ad99eb42b` |
| `zkcfa-plonk/plonk` | upstream-compatible submodule pin | `4fc762ac433a942939ad43a3b29050a26ce52533` |
| `zekra` | `dev` | `fd06a6a47f0b14249e4911d9b39f3b9df82c2914` |
| `zekra/ZEKRA` | unmodified upstream pin | `01a0152bfd9812a0569dce19965e7e92df30015d` |
| `zkcfa-tracer` | `enhanced` | `80d577f61bcc9c716682285f0e6ed88ebc2194da` |

Source remotes at import time were
[`zkcfa-binius64`](https://github.com/zkpuser/zkcfa-binius),
[`Binius64`](https://github.com/binius-zk/binius64),
[`zkcfa-plonk`](https://github.com/zkpuser/zkcfa-plonk),
[`PLONK`](https://github.com/zkpuser/plonk),
[`zekra`](https://github.com/zkpuser/zkcfa-zekra),
[`ZEKRA`](https://github.com/HeiniDebes/ZEKRA), and
[`zkcfa-tracer`](https://github.com/zkpuser/zkcfa-tracer).

The former component-repository histories were intentionally not imported.
The root [`.gitmodules`](../.gitmodules) records the three retained dependencies.

The imported `zekra/dev` wrapper snapshot originally selected ZEKRA commit
`eaf1095`, which differs only in seven generated CRC32 input files. This
repository pins the unmodified upstream artifact at `01a0152`. The original
experiments used `eaf1095`.

The selected PLONK `4fc762a` commit retains the validated upstream-compatible
relation. Measurements originally collected with `c00acbe` retain that revision
in their source records.

The submodules are configured to the artifact-maintained forks
[`zkpuser/binius64`](https://github.com/zkpuser/binius64),
[`zkpuser/plonk`](https://github.com/zkpuser/plonk), and
[`zkpuser/ZEKRA`](https://github.com/zkpuser/ZEKRA). The dependency pins are
recorded by the Git links and selected during recursive initialization. The
pipeline fails early with an explicit error if a required submodule is
uninitialized, dirty, or at a different commit.
