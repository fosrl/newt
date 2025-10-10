# How to apply patches

These patches were generated from the working tree without commits. You can apply them in one shot or in topic order.

One shot (recommended during review):

```bash
git apply patches/00_all_changes.patch
```

Topic order:

```bash
git apply patches/01_proxy_multitunnel.patch
git apply patches/02_reconnect_rtt.patch
git apply patches/03_constants_docs.patch
```

Rollback (restore to HEAD and clean untracked files):

```bash
git restore --source=HEAD --worktree --staged .
git clean -fd
```

