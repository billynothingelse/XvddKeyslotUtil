# XvddKeyslotUtil
Dump the CIK (Content Instance Key) for current registered MSIXVC packages from the XVDD kernel driver.

## Usage
```
usage: xvddkeyslotutil --help=string [options] ...
options:
  -h, --help      print usage (string)
  -o, --output    output path for *.cik files
  -d, --kb        kernel-bridge driver path (to kernel-bridge.sys)
```

## Decryption & Extraction

Use [xvdtool by emoose](https://github.com/emoose/xvdtool).

## Contributions
### [Billy Hulbert](https://github.com/billyhulbert)
#### Reverse engineering XVDD.sys and writing PoC
### [tuxuser](https://github.com/tuxuser)
#### Assisting with reverse engineering, previous research and extending the command line application
