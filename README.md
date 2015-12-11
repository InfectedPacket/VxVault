# VxVault

## Summary

VxVault is a malware management program to automatically download and classify malware samples. VxVault downloads malware samples from links from online sources such as webpages or RSS feeds, downloads them and attempts to identify the malware using VirusTotal. It then sort the malware onto a local file system and into a SQLite database. Furthermore, each sample is archived into a password protected 7zip file for sharing and protection against anti-virus (AV) deletion. This program targets malware researchers, students and other IT security professionals.

## Requirements

VxVault is a command-line based Python script. As such, Python 2.7 or later is required to use this application. Additional modules are also required for VxVault to function properly:

### sqlite3

VxVault stores malware data into a SQLite file. It relies on the sqlite3 python module to do so. It should be included with recent version of Python, otherwise use the PIP with the following command in a Command Prompt or shell:

```
pip install pysqlite
```

### simplejson

This program leverages the API VirusTotal extensively to identify malware sample and a such, needs to parse JSON response, which is done with the simplejson module. Using PIP, you can install this module with:

```
pip install simplejson
```

### feedparser

Some 'hunters', i.e. threads which seeks new malware samples, uses RSS feeds to obtain new information. The feedparser module allows for quick parsing of such sources and can be installed with

```
pip install feedparser
```


## Usage

To use VxVault, consult the options available below:

```
usage: vxvault -a PATH_OR_URL|-i PATH|--hunt -vt APIKEY [-p PASSWORD] [-v]| [-h|--help]


optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit

Vault Options:
  Sets basic options for the vault.

  -b BASE, --base BASE  Specifies the base directory of the vault.
  -vt VTAPIKEY, --vtapi VTAPIKEY
                        Specifies the public key to use the API of VirusTotal.
  -a NEWFILE, --add NEWFILE
                        File or directory of a single malware to add to the
                        vault.
  -i IMPORT_DIR, --import IMPORT_DIR
                        Specifies a directory containing multiple malware to
                        import into the vault.
  -p PASSWORD, --password PASSWORD
                        Specifies the password to used for encrypting archives
                        containing the malware.
  --hunt                Starts the vault in hunt mode.
  --verbose             Displays diagnostic messages while VxVault is running.
```

## Examples


### Adding a new malware sample

The following command will add a single file, named badfile.exe to the vault. The -b options specified the location of the vault, while the -vt option is used to retrieve scan information for the file. 

```
python vxvault.py -b c:\vx\ -vt sd56fs65sd65fg4s6d5g4s65g4s6d5g4sd54 -a c:\tmp\badfile.exe
```

If no previous vault has been created in the directory, VxVault will ask you if you want to created one prior to starting.

To add a malware containing multiple files, copy all the files into a single directory and use the -a options with the directory containing the files:

```
python vxvault.py -b c:\vx\ -vt sd56fs65sd65fg4s6d5g4s65g4s6d5g4sd54 -a c:\tmp\ratfiles\
```

### Adding multiple samples

If you need to add multiple samples at the same time, copy all the samples, either files or directories into a directory, and use the -i options:

```
python vxvault.py -b c:\vx\ -vt sd56fs65sd65fg4s6d5g4s65g4s6d5g4sd54 -i c:\tmp\samples\
```

### Hunting mode

The command below will use the C:\vx directory as the base directory for the vault. It will then enter into 'hunt' mode, which will spawn 'hunters' threads. The threads will each poll their different data sources for new malware samples and download them to the vault.

```
python vxvault.py -b c:\vx\ -vt sd56fs65sd65fg4s6d5g4s65g4s6d5g4sd54 --hunt
```

## Issues and Bugs

Please report any bugs with this program to the Github page of this project at https://github.com/InfectedPacket/VxVault.


