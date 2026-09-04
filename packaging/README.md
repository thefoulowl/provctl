# Packaging

Three package definitions, one per major distro family. All three build the
same way underneath: `CGO_ENABLED=0 go build -trimpath ./cmd/provctl` — the
binary has no C dependencies (both `cilium/ebpf` and `modernc.org/sqlite` are
pure Go), so it's a single static binary with no runtime library deps. The
only real runtime requirement is the kernel itself: BTF exposed at
`/sys/kernel/btf/vmlinux` (5.8+), and root/`CAP_BPF`+`CAP_PERFMON` to run
`provctl watch`.

`-trimpath` matters here specifically because these are *distro* packages:
without it, the binary embeds the packager's own local build-machine paths
(e.g. `/home/alice/go/pkg/mod/...`), which is both a minor info leak and
breaks build reproducibility. Its one side effect: rpm's automatic
debuginfo/debugsource split needs those real paths to work, so the spec
disables it (`%global debug_package %{nil}`) rather than fighting it — Go's
DWARF output isn't structured for rpm's debugsource model anyway, so this is
standard practice for Go (and Rust) rpm packages, not a workaround-of-a-fix.

All three also install `systemd/provctl.service`, which runs
`provctl watch --quiet` as a system service. It's not enabled by default.

## Fedora / RHEL family (`.rpm`)

```sh
rpmbuild -bb packaging/rpm/provctl.spec
```

Downloads the source tarball from the GitHub release tag matching the
`Version:` field in the spec, so a matching tag must exist upstream first.

## Debian / Ubuntu (`.deb`)

```sh
cd packaging/deb
dpkg-buildpackage -us -uc -b
```

Run from a checkout of the full repo with `packaging/deb/debian/` as the
`debian/` directory — e.g. symlink or copy `packaging/deb/debian` to the
repo root before building, or use `dpkg-buildpackage --build-dir`. Requires
`debhelper` (`>= 13`) and `golang-go` (`>= 1.25`).

**Not build-tested on a real Debian/Ubuntu toolchain** — the rpm and AUR
packages below were, but there's no `dpkg-dev`/`debhelper` available on the
machine these were written on. Debian's automatic `dbgsym` split works
differently from rpm's (it packages compressed debug sections rather than
enumerating original source file paths), so it likely doesn't hit the same
`-trimpath` conflict the rpm spec needed a fix for — but "likely" isn't
"verified". Run `debuild -us -uc -b` once locally and check for warnings
before signing and uploading anywhere.

## Arch (AUR)

```sh
cd packaging/aur
makepkg -si
```

`sha256sums` and `.SRCINFO` are already filled in for the current release —
both build-verified end to end with a real `makepkg` run (downloaded the
actual release tarball, checksummed it, built, packaged; the resulting
binary runs). `.SRCINFO` was generated with `makepkg --printsrcinfo`, not
hand-written, so it's guaranteed to match the `PKGBUILD`.

To publish or update the AUR listing itself (needs an AUR account with an
SSH key registered):

```sh
git clone ssh://aur@aur.archlinux.org/provctl.git aur-provctl
cp packaging/aur/PKGBUILD packaging/aur/.SRCINFO aur-provctl/
cd aur-provctl
git add PKGBUILD .SRCINFO
git commit -m "provctl 0.1.1-1"
git push
```

## Releasing a new version

1. Bump the version in `packaging/rpm/provctl.spec` (`Version:`),
   `packaging/deb/debian/changelog` (new entry), and
   `packaging/aur/PKGBUILD` (`pkgver`).
2. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. Recompute the AUR tarball checksum (see above) and update the PKGBUILD.
