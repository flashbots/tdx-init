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

Layout of a newly formatted disk: the LUKS2 header in the first 16 MiB, the header's MAC in sector 32768, and
the encrypted data from 17 MiB on, with 4 KiB crypt sectors. Disks formatted by earlier versions (data at
sector 32769, 512-byte sectors) keep working: the data offset and sector size are read from the header.
