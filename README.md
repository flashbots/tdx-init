# tdx-init

A utility for secure disk encryption and SSH configuration in TDX (Trusted Domain Extensions) VMs.
Currently designed specifically for Flashbots BoB VMs.

## Functionality

- Allows VM operator to provision a VM with a searcher's SSH key
- Stores searcher's SSH key directly in LUKS2 header
- Automatically sets up persistent encrypted disk once searcher has provided a LUKS2 passphrase

## Usage

```
tdx-init wait-for-key     # Wait for SSH key via HTTP or extract from existing LUKS header
tdx-init set-passphrase   # Set up or mount an encrypted disk with passphrase
```

- `tdx-init wait-for-key` should be called during the init process (before anything requiring peristant storage is mounted)
- `tdx-init set-passphrase` should be called after the SSH key has been established directly by the searcher through an authenticated channel

## Persistent disk

The first existing match of these globs is used as the persistent disk:

1. Patterns listed in `/etc/tdx-init/disk-glob` (one per line), if the file exists
2. `/dev/disk/by-path/*10`: Azure, SCSI LUN 10
3. `/dev/disk/by-id/google-data`: GCP
4. `/dev/disk/by-id/virtio-persistent`: bare-metal QEMU/libvirt, a virtio-blk disk with serial `persistent`

New disks use a 16 MiB LUKS2 header, a header MAC at byte offset 16 MiB, and encrypted data starting at 17 MiB with 4 KiB encryption sectors.
