# ucfs-claimant-api-replayer

## An AWS lambda which receives requests and a response payload, to replay against the v1 UCFS Claimant API in London to assert responses are equal.

This repo contains Makefile to fit the standard pattern.
This repo is a base to create new non-Terraform repos, adding the githooks submodule, making the repo ready for use.

After cloning this repo, please run:  
`make bootstrap`


## Environment variables

|Variable name|Example|Description|
|---|:---:|---:|
|API_REGION| eu-west-1 |The region where the API gateway is located |
|V1_KMS_REGION| eu-west-2 |The region of the V1 Lambdas KMS |
|V2_KMS_REGION| eu-west-1 |The region of the V2 Lambdas KMS |
|ENVIRONMENT| DEV or PROD |The environment the lambda is running in|
|APPLICATION| ucfs-claimant-api-replayer |The name of the application |
|LOG_LEVEL| INFO or DEBUG |The logging level of the Lambda |
|API_HOSTNAME|api.{environment_short_name}.dataworks.dwp.gov.uk|The FQDN of AWS Gateway API |

## Testing

There are tox unit tests in the module. To run them, you will need the module tox installed with `pip install tox`, 
then go to the root of the module and simply run `tox` to run all the unit tests.

**The test may also be ran via `make unittest`**

**You should always ensure they work before making a pull request for your branch.**

**If tox has an issue with Python version you have installed, you can specify such as `tox -e py38`.**

