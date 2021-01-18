import logging
import boto3
import argparse
import os
import sys
import socket
import json
import datetime
import requests
import base64
from aws_requests_auth.aws_auth import AWSRequestsAuth
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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

    _args = parser.parse_args()

    # Override arguments with environment variables where set
    if "AWS_PROFILE" in os.environ:
        _args.aws_profile = os.environ["AWS_PROFILE"]

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
        _args.hostname = os.environ["API_HOSTNAME"]

    required_args = ["api_region", "v1_kms_region", "v2_kms_region", "api_hostname"]
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


args = None
logger = None


def handler(event, context):
    global args
    args = get_parameters()
    global logger
    logger = setup_logging(args.log_level)
    logger.info(f"Event: {event}")

    session = boto3.session.Session()
    default_credentials = session.get_credentials().get_frozen_credentials()
    datetimenow = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    request_auth = AWSRequestsAuth(
        aws_access_key=default_credentials.access_key,
        aws_secret_access_key=default_credentials.secret_key,
        aws_token=default_credentials.token,
        aws_host=f"{args.api_hostname}",
        aws_region=f"{args.api_region}",
        aws_service="execute-api",
    )

    try:
        original_request = json.loads(event["Body"]["originalRequest"])
        original_response = json.loads(event["Body"]["originalResponse"])
    except KeyError as e:
        logger.error("Attempted to extract event items but was unable.")
        logger.error(e)
        raise e

    actual_response = replay_original_request(
        request_auth, original_request, datetimenow, args
    )

    decrypted_original_response = decrypt_response(
        original_response, original_request, args.v2_kms_region
    )
    decrypted_actual_response = decrypt_response(
        actual_response, original_request, args.v1_kms_region
    )

    if compare_responses(
        decrypted_original_response, decrypted_actual_response, original_request
    ):
        logger.info('Final result", "status": "match')
    else:
        logger.info('Final result", "status": "miss')


def replay_original_request(request_auth, original_request, date_time_now, args):
    request_parameters = "&".join([f"{k}={v}" for k, v in original_request.items()])

    headers = {
        "Content-Type": "application/json",
        "X-Amz-Date": date_time_now,
    }

    logger.info(f'Requesting data from AWS API", "api_hostname": "{args.hostname}')
    request = requests.post(
        f"https://{args.api_hostname}/ucfs-claimant/v2/getAwardDetails",
        data=request_parameters,
        auth=request_auth,
        headers=headers,
    )

    logger.info(
        f'Received response from AWS API", "api_hostname": "{args.hostname}", "response_code": "{request.status_code}'
    )

    return json.loads(request.text)


def decrypt_response(response: dict, request: dict, region: str) -> dict:
    # Create a deep copy of the response to keep the function pure
    response = response.copy()
    session = boto3.session.Session(profile_name="decrypt", region_name=region)

    client = session.client("kms")

    for period in response.get("assessmentPeriod", []):
        amount = period.get("amount")

        take_home_pay = base64.urlsafe_b64decode(amount.get("takeHomePay"))
        cipher_text_blob = base64.urlsafe_b64decode(amount.get("cipherTextBlob"))

        kms_response = client.decrypt(CiphertextBlob=cipher_text_blob)
        data_key = kms_response.get("Plaintext")

        nonce_size = 12
        # Takes the first 12 characters from the take_home_pay string
        nonce = take_home_pay[:nonce_size]

        # Takes the remaining characters from the take_home_pay string following the first 12
        take_home_pay = take_home_pay[nonce_size:]

        aesgcm = AESGCM(data_key)

        try:
            logger.info(
                f'Beginning to decrypt data", '
                f'"transaction_id": {request.get("transaction_id")}, '
                f'"from_date": {request.get("from_date")}, '
                f'"to_date": {request.get("to_date")}'
            )
            take_home_pay = aesgcm.decrypt(nonce, take_home_pay, None).decode("utf-8")

            amount["takeHomePay"] = take_home_pay
            del amount["ciperTextBlob"]
            del amount["keyId"]

            period["amount"] = amount

        except Exception as e:
            logger.error(
                f'Failed to decrypt data", '
                f'"transaction_id": {request.get("transaction_id")}, '
                f'"from_date": {request.get("from_date")}, '
                f'"to_date": {request.get("to_date")}'
            )
            logger.error(e)
            raise e

    return response


def compare_responses(original, actual, request):
    match = True
    if original["claimantFound"] != actual["claimantFound"]:
        match = False
        logger.info(
            f"Claimant found doesn't match, "
            f'expected {original["claimantFound"]} from replayed response but got {actual["claimantFound"]}'
        )

    if original.get("suspendedDate"):
        if original.get("suspendedDate") == actual.get("suspendedDate"):
            logger.info('Suspended date is a match", "status": "match')
        else:
            match = False
            logger.info(
                'Suspended date expected but does not match or was not found in replayed response", "status": "miss'
            )

    else:
        if actual.get("suspendedDate"):
            match = False
            logger.info(
                'Suspended date not expected but found in replayed response", "status": "miss'
            )
        else:
            logger.info(
                'Suspended date is not expected and not present in either original or replayed response", '
                '"status": "match'
            )

    logger.info(
        f'Comparing responses", '
        f'"transaction_id": {request.get("transactionId")}, '
        f'"from_date": {request.get("fromDate")}, '
        f'"to_date": {request.get("toDate")}'
    )

    expected_list = original["assessmentPeriod"]
    actual_list = actual["assessmentPeriod"]

    all_assessment_period = {
        "expected_list": expected_list.copy(),
        "actual_list": actual_list.copy(),
    }

    for expected_record in expected_list:
        if expected_record in actual_list:
            logger.info(
                f'Match for assessment period", "status": "match", '
                f'"transaction_id": {request["transactionId"]}, '
                f'"AP_from_date": {expected_record.get("fromDate")},'
                f'"AP_to_date": {expected_record.get("toDate")}'
            )

            all_assessment_period["actual_list"].remove(expected_record)
            all_assessment_period["expected_list"].remove(expected_record)

    for record in all_assessment_period["expected_list"]:
        match = False
        logger.info(
            f'No match for original response assessment period in replayed assessment period", "status": "miss", '
            f'"transaction_id": {request["transactionId"]}, '
            f'"AP_from_date": {record.get("fromDate")},'
            f'"AP_to_date": {record.get("toDate")}'
        )

    for record in all_assessment_period["actual_list"]:
        match = False
        logger.info(
            f'No match for replayed assessment period in original response assessment period", "status": "miss", '
            f'"transaction_id": {request["transactionId"]}, '
            f'"AP_from_date": {record.get("fromDate")},'
            f'"AP_to_date": {record.get("toDate")}'
        )

    return match


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
