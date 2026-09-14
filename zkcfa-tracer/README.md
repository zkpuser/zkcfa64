# ZKCFA trace provider

The maintained system is in [`provider/`](provider/). It provisions a raw24
typed CFG, records a complete root-scoped QEMU path, produces canonical trace
evidence, and creates the authority/device-signed handoff consumed by Binius64.

The paper's acquisition adapters, pinned benchmark sources, signed-bundle
evaluation harness, and baseline compression helper are under
[`research/`](research/README.md). They are not imported by the maintained
provider.

See [`provider/README.md`](provider/README.md) for the runnable pipeline and
[`provider/SECURITY.md`](provider/SECURITY.md) for the trust boundary.

## License

Except for third-party material carrying its own notice, the original code and
documentation in this component are dual-licensed under either
[Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

Vendored sources, benchmark programs, and other third-party material under
`research/` retain their original licenses and copyright notices. The
component-level licenses do not relicense those files.
