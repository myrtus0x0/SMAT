# S.M.A.T

## Capabilities

### MWDB
- [X] query for config entries of samples
- [ ] file upload
- [ ] file download
- [ ] config upload

### Triage
- [X] get all JA3s and JA3 for a family
- [X] get config details for a sample
- [X] get pcaps from a malware family (meant to use in conjunction with PCAP processing tools)
- [X] submit samples to the Tria.ge platform

### Malware Bazaar
- [X] check if samples exist in the respository
- [X] get medata for all samples in a family over the last 24 hours
- [X] upload samples to the platform

### URLHaus
- [X] upload URLs to the platform
- [X] check if the URL exists in the dataset

### ThreatFox
- [X] pull all C2s over the last seven days

## Setup
All the routing and auth is controlled via environment variables. To use all of the platforms, the following environment varialbes will have to be set
```
export TRIAGE_KEY=""
export BAZA_KEY=""
export URLHAUS=""
export MWDB_KEY=""
export MWDB_HOST="mwdb.cert.pl"
export MWDB_PROTO="<https://><http://>"
```

## Examples
```
SMAT allows for anaylysts to quickly extract information about malware families, download samples, upload samples, download pcaps and extract config details from common malware families.

Usage:
  smat [command]

Available Commands:
  bazaar      all subcommands relating to the malware bazaar platform
  fox         all subcommands relating to the threatfox platform
  help        Help about any command
  mwdb        all subcommands relating to CERT.PLs MWDB platform
  triage      all subcommands relating to the triage platform
  urlhaus     all subcommands relating to the urlhaus platform

Flags:
  -h, --help   help for smat

Use "smat [command] --help" for more information about a command.

```

```
all subcommands relating to the malware bazaar platform

Usage:
  smat bazaar [command]

Available Commands:
  check       checks if a sample exists within malware bazaar
  get_family  returns metadata for all samples uploaded for a family within the last 24 hours
  upload      uploads a sample or samples to malware bazaar

Flags:
  -h, --help          help for bazaar
  -t, --tags string   comma split list of tags to apply

Use "smat bazaar [command] --help" for more information about a command.
```

```
all subcommands relating to the triage platform

Usage:
  smat triage [command]

Available Commands:
  get_JA3s    returns all ja3 and ja3s signatures for specific malware family
  get_config  returns all config details for the malware if it exists
  get_pcaps   returns all pcap ng files for a specific family
  submit      submits a file to the Hatching triage platform

Flags:
  -h, --help   help for triage

Use "smat triage [command] --help" for more information about a command.

```

```
all subcommands relating to the urlhaus platform

Usage:
  smat urlhaus [command]

Available Commands:
  check       checks if a url or set of urls exists within urlhaus
  submit      uploads the list of URLs to urlhaus

Flags:
  -h, --help   help for urlhaus

Use "smat urlhaus [command] --help" for more information about a command.
```
