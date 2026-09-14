# Provider input

The PLONK executable consumes the same directory shape and raw tracer artifacts as
`zkcfa-binius64`:

```text
input/APP/run/bundle/                 # complete QEMU path
input/APP/compressed/run/bundle/      # signed stack-safe path
```

Each bundle has exactly this shape:

```text
bundle/
├── public/
│   ├── registry.json
│   └── report.json
└── private/
    ├── worker.json
    ├── translator
    ├── typed_cfg
    └── recorded_path
```

`translator`, `typed_cfg`, and `recorded_path` use the same canonical raw24 syntax as the
Binius64 backend. The signed public files are backend-specific: a PLONK bundle selects
`backend=plonk` and binds Poseidon `H_ep` and `H_cfg`, so an already signed Binius64/SHA bundle
cannot be substituted even when its three tracer artifacts are byte-identical.

On Unix, `private/` must not be accessible by group or other users, and its four files must also
be non-executable and inaccessible to group or other users. A provider can satisfy this with
mode `0700` on the directory and `0600` on the files. Symlinks and additional bundle files are
rejected.

Generated bundles and private worker handoffs are ignored by Git. The authority public key used
to verify a bundle must come from an independent trust store, not from the bundle itself.
