import logging
import boto3
import argparse
import os
import sys
import socket
import json


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
        description="Convert S3 objects into Kafka messages"
    )

    # Parse command line inputs and set defaults
    parser.add_argument("--aws-profile", default="default")
    parser.add_argument("--aws-region", default="eu-west-2")
    parser.add_argument("--environment", default="NOT_SET")
    parser.add_argument("--application", default="NOT_SET")
    parser.add_argument("--log-level", default="INFO")

    _args = parser.parse_args()

    # Override arguments with environment variables where set
    if "AWS_PROFILE" in os.environ:
        _args.aws_profile = os.environ["AWS_PROFILE"]

    if "AWS_REGION" in os.environ:
        _args.aws_region = os.environ["AWS_REGION"]

    if "ENVIRONMENT" in os.environ:
        _args.environment = os.environ["ENVIRONMENT"]

    if "APPLICATION" in os.environ:
        _args.application = os.environ["APPLICATION"]

    if "LOG_LEVEL" in os.environ:
        _args.application = os.environ["LOG_LEVEL"]

    required_args = []
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


args = get_parameters()
logger = setup_logging(args.log_level)


def handler(event, context):
    #     {"originalRequest": {"request_stuff": "stuff"}, "originalResponse": {"response"}}

    loaded_event = json.loads(event)
    api_request = loaded_event["Body"]["originalRequest"]
    expected_response = loaded_event["Body"]["originalResponse"]

    actual_response = forward_original_request(api_request)

    compare_responses(expected_response, actual_response)


def forward_original_request(api_request):
    # Raw body query string to v1
    # nino=XX&transactionId=X&fromDate=X&toDate=X
    # nino - encrypted
    # transactionId - int
    # fromDate YYYYMMDD
    # toDate YYYYMMDD

    #  Claimant found false is a valid response - london must match.
    # {"claimantFound": false,
    #  "assessmentPeriod": []}
    #
    return "stfu"


def compare_responses(expected_response, actual_response):
    return "stfu"


if __name__ == "__main__":
    try:
        boto3.setup_default_session(
            profile_name=args.aws_profile, region_name=args.aws_region
        )
        logger.info(os.getcwd())
        json_content = json.loads(open("resources/event.json", "r").read())
        handler(json_content, None)
    except Exception as err:
        logger.error(f'Exception occurred for invocation", "error_message": "{err.msg}')
