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

TODO.
