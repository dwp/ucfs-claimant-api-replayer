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
    parser.add_argument("--mismatch-lambda-name")
    parser.add_argument("--mismatch-lambda-region")

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

    if "MISMATCH_LAMBDA_NAME" in os.environ:
        _args.mismatch_lambda_name = os.environ["MISMATCH_LAMBDA_NAME"]

    if "MISMATCH_LAMBDA_REGION" in os.environ:
        _args.mismatch_lambda_region = os.environ["MISMATCH_LAMBDA_REGION"]

    required_args = [
        "api_region",
        "v1_kms_region",
        "v2_kms_region",
        "api_hostname",
        "mismatch_lambda_name",
        "mismatch_lambda_region",
    ]
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


def get_date_time_now():
    return datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


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

    lambda_client = boto3.client("lambda", region_name=args.mismatch_lambda_region)

    request_auth = AWSRequestsAuth(
        aws_access_key=default_credentials.access_key,
        aws_secret_access_key=default_credentials.secret_key,
        aws_token=default_credentials.token,
        aws_host=f"{args.api_hostname}",
        aws_region=f"{args.api_region}",
        aws_service="execute-api",
    )

    try:
        original_request = json.loads(event["originalRequest"])
        original_response = json.loads(event["originalResponse"])
    except KeyError as e:
        logger.error("Attempted to extract event items but was unable.")
        logger.error(e)
        raise e

    actual_response = replay_original_request(request_auth, original_request, args)

    decrypted_original_response = decrypt_response(
        original_response, original_request, args.v2_kms_region
    )
    decrypted_actual_response = decrypt_response(
        actual_response, original_request, args.v1_kms_region
    )

    if compare_responses(
        decrypted_original_response,
        decrypted_actual_response,
        original_request,
        lambda_client,
    ):
        logger.info(
            f'Final result", "status": "match", '
            f'"nino": "{original_request.get("nino")}", '
            f'"transaction_id": "{original_request.get("transaction_id")}", '
            f'"from_date": "{original_request.get("from_date")}", '
            f'"to_date": "{original_request.get("to_date")}'
        )
    else:
        logger.info(
            f'Final result", "status": "miss", '
            f'"nino": "{original_request.get("nino")}", '
            f'"transaction_id": "{original_request.get("transaction_id")}", '
            f'"from_date": "{original_request.get("from_date")}", '
            f'"to_date": "{original_request.get("to_date")}'
        )


def replay_original_request(request_auth, original_request, args):
    non_empty_request_parameters = []
    for k, v in original_request.items():
        if v is not None and v != "":
            non_empty_request_parameters.append(f"{k}={v}")

    request_parameters = "&".join(non_empty_request_parameters)

    headers = {
        "Content-Type": "application/json",
        "X-Amz-Date": get_date_time_now(),
    }

    logger.info(
        f'Requesting data from AWS API", "api_hostname": "{args.api_hostname}", '
        f'"original_request": "{original_request}'
    )

    try:
        request = requests.post(
            f"https://{args.api_hostname}/ucfs-claimant/v1/getAwardDetails",
            data=request_parameters,
            auth=request_auth,
            headers=headers,
        )
    except Exception as e:
        logger.error(
            f'Failed to communicate with AWS API", "api_hostname": "args.api_hostname", '
            f'"api_request_address": "https://{args.api_hostname}/ucfs-claimant/v1/getAwardDetails",'
            f'"exception": "{e}'
        )
        raise e

    logger.info(
        f'Received response from AWS API", "api_hostname": "{args.api_hostname}", "response_code": "{request.status_code}'
    )

    return json.loads(request.text)


def decrypt_response(response: dict, request: dict, region: str) -> dict:
    # Create a deep copy of the response to keep the function pure
    response = response.copy()
    session = boto3.session.Session(region_name=region)

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
                f'"nino": "{request.get("nino")}", '
                f'"transaction_id": "{request.get("transactionId")}", '
                f'"from_date": "{request.get("fromDate")}", '
                f'"to_date": "{request.get("toDate")}'
            )
            take_home_pay = aesgcm.decrypt(nonce, take_home_pay, None).decode("utf-8")

            amount["takeHomePay"] = take_home_pay

            if amount["cipherTextBlob"]:
                del amount["cipherTextBlob"]
            if amount["keyId"]:
                del amount["keyId"]

            period["amount"] = amount

        except Exception as e:
            logger.error(
                f'Failed to decrypt data", '
                f'"nino": "{request.get("nino")}", '
                f'"transaction_id": "{request.get("transactionId")}", '
                f'"from_date": "{request.get("fromDate")}", '
                f'"to_date": "{request.get("toDate")}'
            )
            logger.error(e)
            raise e

        logger.info(
            f'Successfully decrypted assessment period", '
            f'"nino": "{request.get("nino")}", '
            f'"transaction_id": "{request.get("transactionId")}", '
            f'"from_date": "{request.get("fromDate")}", '
            f'"to_date": "{request.get("toDate")}'
        )
    return response


def compare_responses(original, actual, request, lambda_client):
    if original["claimantFound"] != actual["claimantFound"]:
        logger.info(
            f'Claimant found does not match, expected {original["claimantFound"]} from replayed response '
            f'but got {actual["claimantFound"]}. Forwarding to mismatch handler", '
            '"status": "miss", '
            f'"nino": "{request.get("nino")}", '
            f'"transaction_id": "{request.get("transactionId")}", '
            f'"from_date": "{request.get("fromDate")}", '
            f'"to_date": "{request.get("toDate")}'
        )
        forward_to_mismatch_handler(
            request.get("nino"), request.get("transactionId"), "", lambda_client, args
        )
        return False

    if original.get("suspendedDate"):
        if original.get("suspendedDate") == actual.get("suspendedDate"):
            logger.info(
                'Suspended date is a match", "status": "match", '
                f'"nino": "{request.get("nino")}", '
                f'"transaction_id": "{request.get("transactionId")}", '
                f'"from_date": "{request.get("fromDate")}", '
                f'"to_date": "{request.get("toDate")}'
            )
        else:
            logger.info(
                "Suspended date expected but does not match or was not found in replayed response. "
                'Forwarding to mismatch handler", "status": "miss", '
                f'"nino": "{request.get("nino")}", '
                f'"transaction_id": "{request.get("transactionId")}", '
                f'"from_date": "{request.get("fromDate")}", '
                f'"to_date": "{request.get("toDate")}'
            )
            forward_to_mismatch_handler(
                request.get("nino"),
                request.get("transactionId"),
                "",
                lambda_client,
                args,
            )
            return False
    elif actual.get("suspendedDate"):
        logger.info(
            "Suspended date not expected but found in replayed response. "
            'Forwarding to mismatch handler", "status": "miss", '
            f'"nino": "{request.get("nino")}", '
            f'"transaction_id": "{request.get("transactionId")}", '
            f'"from_date": "{request.get("fromDate")}", '
            f'"to_date": "{request.get("toDate")}'
        )
        forward_to_mismatch_handler(
            request.get("nino"),
            request.get("transactionId"),
            "",
            lambda_client,
            args,
        )
        return False
    else:
        logger.info(
            'Suspended date is not expected and not present in either original or replayed response", '
            '"status": "match", '
            f'"nino": "{request.get("nino")}", '
            f'"transaction_id": "{request.get("transactionId")}", '
            f'"from_date": "{request.get("fromDate")}", '
            f'"to_date": "{request.get("toDate")}'
        )

    logger.info(
        f'Comparing responses", '
        f'"nino": "{request.get("nino")}", '
        f'"transaction_id": "{request.get("transactionId")}", '
        f'"from_date": "{request.get("fromDate")}", '
        f'"to_date": "{request.get("toDate")}'
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
                f'"nino": "{request.get("nino")}", '
                f'"transaction_id": "{request.get("transactionId")}", '
                f'"from_date": "{request.get("fromDate")}", '
                f'"to_date": "{request.get("toDate")}'
            )

            all_assessment_period["actual_list"].remove(expected_record)
            all_assessment_period["expected_list"].remove(expected_record)

    assessment_periods_match = True
    for record in all_assessment_period["expected_list"]:
        logger.info(
            f"No match for original response assessment period in replayed assessment period. "
            f'Forwarding to mismatch handler", "status": "miss", '
            f'"nino": "{request.get("nino")}", '
            f'"transaction_id": "{request.get("transactionId")}", '
            f'"from_date": "{request.get("fromDate")}", '
            f'"to_date": "{request.get("toDate")}'
        )
        forward_to_mismatch_handler(
            request.get("nino"),
            request.get("transactionId"),
            record.get("amount").get("takeHomePay"),
            lambda_client,
            args,
        )
        assessment_periods_match = False

    for record in all_assessment_period["actual_list"]:
        logger.info(
            f"No match for replayed assessment period in original response assessment period. "
            f'Forwarding to mismatch handler", "status": "miss", '
            f'"nino": "{request.get("nino")}", '
            f'"transaction_id": "{request.get("transactionId")}", '
            f'"from_date": "{request.get("fromDate")}", '
            f'"to_date": "{request.get("toDate")}'
        )
        forward_to_mismatch_handler(
            request.get("nino"),
            request.get("transactionId"),
            record.get("amount").get("takeHomePay"),
            lambda_client,
            args,
        )
        assessment_periods_match = False

    return assessment_periods_match


def forward_to_mismatch_handler(
    nino, transaction_id, take_home_pay, lambda_client, args
):
    logger.info(
        f'Invoking mismatch handler lambda", '
        f'"nino": "{nino}", '
        f'"transaction_id", "{transaction_id}",'
        f'"take_home_pay": "{take_home_pay}",'
        f'"mismatch_lambda_name": "{args.mismatch_lambda_name}",'
        f' "mismatch_lambda_region": "{args.mismatch_lambda_region}'
    )

    lambda_payload = json.dumps(
        {"nino": nino, "transaction_id": transaction_id, "take_home_pay": take_home_pay}
    )

    try:
        response = lambda_client.invoke(
            FunctionName=args.mismatch_lambda_name,
            InvocationType="Event",
            Payload=lambda_payload,
        )

        logger.info(f'Invoked lambda successfully", "response": "{response}')

    except Exception as e:
        logger.error(f'Failed to invoke lambda", "exception": {e}')
        raise e


if __name__ == "__main__":
    try:
        args = get_parameters()
        logger = setup_logging("INFO")

        boto3.setup_default_session(
            profile_name=args.aws_profile, region_name=args.aws_region
        )
        logger.info(os.getcwd())
        json_content = json.loads(open("resources/event.json", "r").read())
        handler(json_content, None)
    except Exception as err:
        logger.error(f'Exception occurred for invocation", "error_message": "{err}')
