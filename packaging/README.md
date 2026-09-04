# Packaging

Three package definitions, one per major distro family. All three build the
same way underneath: `CGO_ENABLED=0 go build ./cmd/provctl` — the binary has
no C dependencies (both `cilium/ebpf` and `modernc.org/sqlite` are pure Go),
so it's a single static binary with no runtime library deps. The only real
runtime requirement is the kernel itself: BTF exposed at
`/sys/kernel/btf/vmlinux` (5.8+), and root/`CAP_BPF`+`CAP_PERFMON` to run
`provctl watch`.

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
`debhelper` (`>= 13`) and `golang-go` (`>= 1.23`).

## Arch (AUR)

```sh
cd packaging/aur
makepkg -si
```

Before submitting to the AUR: replace `sha256sums=('SKIP')` with the real
digest of the release tarball:

```sh
curl -sL https://github.com/thefoulowl/provctl/archive/refs/tags/v0.1.0.tar.gz | sha256sum
```

## Releasing a new version

1. Bump the version in `packaging/rpm/provctl.spec` (`Version:`),
   `packaging/deb/debian/changelog` (new entry), and
   `packaging/aur/PKGBUILD` (`pkgver`).
2. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. Recompute the AUR tarball checksum (see above) and update the PKGBUILD.
