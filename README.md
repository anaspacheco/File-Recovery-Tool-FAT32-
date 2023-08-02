# File Recovery Tool for FAT32 File Systems

## Introduction

Welcome to the File Recovery Tool designed specifically for FAT32 file systems. This powerful utility allows you to recover lost or deleted files with ease, helping you regain access to valuable data.

![image](https://github.com/anaspacheco/File-Recovery-Tool-FAT32-/assets/121977567/ac3bb3de-d469-444f-a47b-38b5bcf72ae1)

Src: https://recoverit.wondershare.com/file-system/fat32-file-system.html
## Usage

To get started, follow the instructions below:

1. Clone this repository to your local machine.
2. Run the tool using the following command: `./file_rec`

## Command Line Options

The File Recovery Tool supports the following command line options:

### Print File System Information

Use the `-i` flag to print detailed information about the FAT32 file system.

### List the Root Directory

Utilize the `-l` flag to list the contents of the root directory.

### Recover a Contiguous File

If you need to recover a specific file, employ the following command:

```
./file_rec -r filename [-s sha1]
```

Where:
- `filename`: The name of the file you wish to recover.
- `-s sha1`: (Optional) The SHA-1 hash value of the file for verification purposes.

Please note that the tool will attempt to recover **contiguous** files. Noncontiguous would require brute-force iterations. 

## Troubleshooting

If you encounter any issues while using the File Recovery Tool please submit them under Issues. 
