# ucfs-claimant-api-replayer

## An AWS lambda which receives requests and a response payload, to replay against the v1 UCFS Claimant API in London to assert responses are equal.

This repo contains Makefile to fit the standard pattern.
This repo is a base to create new non-Terraform repos, adding the githooks submodule, making the repo ready for use.

After cloning this repo, please run:  
`make bootstrap`


## Environment variables

api.{environment_short_name}.dataworks.dwp.gov.uk

|Variable name|Example|Description|
|---|:---:|---:|
|API_HOST|api.{environment_short_name}.dataworks.dwp.gov.uk|The FQDN of AWS Gateway API