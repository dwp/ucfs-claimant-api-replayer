import logging
import boto3
import argparse
import os
import sys
import socket

def setup_logging(logger_level):
    the_logger = logging.getLogger()
    for old_handler in the_logger.handlers:
        the_logger.removeHandler(old_handler)

    new_handler = logging.StreamHandler(sys.stdout)

    hostname = socket.gethostname()

    json_format = (
        '{ "timestamp": "%(asctime)s", "log_level": "%(levelname)s", "message": "%(message)s", '
        f'"environment": "{args.environment}", "application": "{args.application}", '
        f'"module": "%(module)s", "process": "%(process)s", '
        f'"thread": "[%(thread)s]", "hostname": "{hostname}" }} '
    )

    new_handler.setFormatter(logging.Formatter(json_format))
    the_logger.addHandler(new_handler)
    new_level = logging.getLevelName(logger_level.upper())
    the_logger.setLevel(new_level)

    if the_logger.isEnabledFor(logging.DEBUG):
        boto3.set_stream_logger()
        the_logger.debug(f'Using boto3", "version": "{boto3.__version__}')

    return the_logger


def get_parameters():
    parser = argparse.ArgumentParser(
        description="An AWS lambda which receives requests and a response payload, "
                    "to replay against the v1 UCFS Claimant API in London to assert responses are equal."
    )

    # Parse command line inputs and set defaults
    parser.add_argument("--aws-profile", default="default")
    parser.add_argument("--environment", default="NOT_SET")
    parser.add_argument("--application", default="NOT_SET")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--api-region", default="eu-west-1")
    parser.add_argument("--v1-kms-region", default="eu-west-2")
    parser.add_argument("--v2-kms-region", default="eu-west-1")
    parser.add_argument("--api-hostname")
    parser.add_argument("--ddb-record-mismatch-table")
    parser.add_argument("--london-paramater-name")
    parser.add_argument("--ireland-parameter-name")

    _args = parser.parse_args()

    # Override arguments with environment variables where set
    if "AWS_PROFILE" in os.environ:
        _args.aws_profile = os.environ["AWS_PROFILE"]

    if "AWS_REGION" in os.environ:
        _args.aws_region = os.environ["AWS_REGION"]

    if "API_REGION" in os.environ:
        _args.api_region = os.environ["API_REGION"]

    if "V1_KMS_REGION" in os.environ:
        _args.v1_kms_region = os.environ["V1_KMS_REGION"]

    if "V2_KMS_REGION" in os.environ:
        _args.v2_kms_region = os.environ["V2_KMS_REGION"]

    if "ENVIRONMENT" in os.environ:
        _args.environment = os.environ["ENVIRONMENT"]

    if "APPLICATION" in os.environ:
        _args.application = os.environ["APPLICATION"]

    if "LOG_LEVEL" in os.environ:
        _args.log_level = os.environ["LOG_LEVEL"]

    if "API_HOSTNAME" in os.environ:
        _args.api_hostname = os.environ["API_HOSTNAME"]

    if "DDB_RECORD_MISMATCH_TABLE" in os.environ:
        _args.ddb_record_mismatch_table = os.environ["DDB_RECORD_MISMATCH_TABLE"]

    if "LONDON_PARAMETER_NAME" in os.environ:
        _args.london_parameter_name = os.environ["LONDON_PARAMETER_NAME"]

    if "IRELAND_PARAMETER_NAME" in os.environ:
        _args.ireland_parameter_name = os.environ["IRELAND_PARAMETER_NAME"]

    if "LONDON_RDS_HOSTNAME" in os.environ:
            _args.london_rds_hostname = os.environ["LONDON_RDS_HOSTNAME"]

    if "IRELAND_RDS_HOSTNAME" in os.environ:
        _args.ireland_rds_hostname = os.environ["IRELAND_RDS_HOSTNAME"]

    required_args = ["api_region", "v1_kms_region", "v2_kms_region", "api_hostname", "ddb_record_mismatch_table", "london_parameter_name", "ireland_parameter_name"]
    missing_args = []
    for required_message_key in required_args:
        if required_message_key not in _args:
            missing_args.append(required_message_key)
    if missing_args:
        raise argparse.ArgumentError(
            None,
            "ArgumentError: The following required arguments are missing: {}".format(
                ", ".join(missing_args)
            ),
        )

    return _args


def get_parameter_store_value(parameter_name, region):
    ssm = boto3.client("ssm", region_name=region)

    try:
        parameter = ssm.get_parameter(
            Name=parameter_name, WithDecryption=False
        )
        return parameter
    except Exception as e:
        logger.error(f'Error attempting to retrieve parameter", "parameter_name": "{parameter_name}", '
                     f'"request_region": "{region}", "exception": "{e}')
        raise e
