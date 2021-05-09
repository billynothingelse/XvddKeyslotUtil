# XvddKeyslotUtil
Dump the CIK (Content Integrity Key) for registered MSIXVC packages that are from the Xbox app on Windows 10. By utilising Kernel-Bridge, this utility directly reads the keyslot table belonging to XVDD, the Xbox Virtual Disk Driver, and store the key data into a file format - for usage with xvdtool.

## Gaming services

ProductID: `9mwpm2cqnlhn`

PFN: `Microsoft.GamingServices_8wekyb3d8bbwe`

## Usage (REQUIRES ADMINISTRATOR!)
```
usage: xvddkeyslotutil [options] ...
options:
  -h, --help      print usage
  -o, --output    output path for *.cik files
  -d, --kb        kernel-bridge driver path (to kernel-bridge.sys)

example:
      xvddkeyslotutil --output "E:\CIK" --kb "E:\Kernel-Bridge\Kernel-Bridge.sys"
```

## Decryption & Extraction

Use [xvdtool by emoose](https://github.com/emoose/xvdtool).
```
example:
# Decrypt
xvdtool -nd -eu -cik "33EC8436-5A0E-4F0D-B1CE-3F29C3955039" -cikfile "E:\CIK\33EC8436-5A0E-4F0D-B1CE-3F29C3955039.cik" "E:\Game\DemoGame.msixvc"
# Extract 
xvdtool -nd -xf "E:\Game\DemoGameExt" ""E:\Game\DemoGame.msixvc"
```

## Changelog

### [v1.0.0] - 2021-05-09

- Added offsets for: 10.0.19041.5035, 10.0.19041.5411
- Implemented heuristic detection of keytables in memory
- More verbosity in logging
- Stop Kernel-Bridge driver before program exits

### [v0.0.1] - 2020-10-01

- Initial release (GamingServices 10.0.19041.3952)
