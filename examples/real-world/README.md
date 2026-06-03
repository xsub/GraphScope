# Real-World Evidence

This directory contains sanitized evidence captured from a real AlmaLinux 10.2
x86_64 VPS. Unlike the synthetic TuxCare demo graph, these files represent
observed packages from an actual running OS instance.

No hostnames, IP addresses, users, paths, environment variables, or secrets are
included. The RPM inventory contains package names and package versions only.

## Files

- `os-release.txt`: `/etc/os-release` from the source system.
- `dnf-repolist.txt`: enabled DNF repositories on the source system.
- `almalinux-10-rpm.list`: package-only inventory generated from RPM.
- `almalinux-10-rpm-evidence.txt`: GraphScope normalized evidence output from
  the RPM inventory.

## Capture

The source host was reached through the user-provided AlmaLinux SSH helper:

```sh
/Users/pawel/ssh-almalinux-vps.sh
```

The inventory was captured with:

```sh
rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n' | sort
```

The normalized evidence output was generated from the repository root with:

```sh
cargo run --quiet -- evidence examples/real-world/almalinux-10-rpm.list > examples/real-world/almalinux-10-rpm-evidence.txt
```

## Result

GraphScope currently parses this as observed RPM runtime evidence:

- `Records`: 666
- `Packages`: 666
- `Ecosystem`: `rpm`
- `Confidence`: `Observed`
