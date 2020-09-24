# XvddKeyslotUtil
Dump the CIK (Content Integrity Key) for current registered MSIXVC packages from the XVDD kernel driver.

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