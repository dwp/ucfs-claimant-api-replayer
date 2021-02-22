import boto3
import os
import json
import datetime
import requests
import base64
from config import *
from query_rds import *
from aws_requests_auth.aws_auth import AWSRequestsAuth
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def get_date_time_now():
    return datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


args = None
logger = None
ddb_client = boto3.resource('dynamodb')


def handler(event, context):
    global args
    args = get_parameters()
    global logger
    logger = setup_logging(args.log_level)

    logger.info(f"Event: {event}")

    session = boto3.session.Session()
    default_credentials = session.get_credentials().get_frozen_credentials()

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
            decrypted_original_response, decrypted_actual_response, original_request
    ):
        logger.info('Final result", "status": "match')
    else:
        logger.info('Final result", "status": "miss')


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

    logger.info(f'Requesting data from AWS API", "api_hostname": "{args.api_hostname}')
    request = requests.post(
        f"https://{args.api_hostname}/ucfs-claimant/v1/getAwardDetails",
        data=request_parameters,
        auth=request_auth,
        headers=headers,
    )

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
                f'"transaction_id": {request.get("transaction_id")}, '
                f'"from_date": {request.get("from_date")}, '
                f'"to_date": {request.get("to_date")}'
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
                f'"transaction_id": {request.get("transaction_id")}, '
                f'"from_date": {request.get("from_date")}, '
                f'"to_date": {request.get("to_date")}'
            )
            logger.error(e)
            raise e

        logger.info(
            f'Successfully decrypted assessment period"   '
            f'"transaction_id": {request.get("transaction_id")}, '
            f'"from_date": {request.get("from_date")}, '
            f'"to_date": {request.get("to_date")}'
        )
    return response


def compare_responses(original, actual, request):
    match = True
    logger.info(f'Original response to compare", "original_response": "{original}')
    logger.info(f'Actual response to compare", "actual_response": "{actual}')

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
            unmatched_responses_request_additional_info(original["nino"], original["transaction_id"])

    else:
        if actual.get("suspendedDate"):
            match = False
            logger.info(
                'Suspended date not expected but found in replayed response", "status": "miss'
            )
            unmatched_responses_request_additional_info(original["nino"], original["transaction_id"])
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
        unmatched_responses_request_additional_info(original["nino"], original["transaction_id"])

    for record in all_assessment_period["actual_list"]:
        match = False
        logger.info(
            f'No match for replayed assessment period in original response assessment period", "status": "miss", '
            f'"transaction_id": {request["transactionId"]}, '
            f'"AP_from_date": {record.get("fromDate")},'
            f'"AP_to_date": {record.get("toDate")}'
        )
        unmatched_responses_request_additional_info(original["nino"], original["transaction_id"])

    return match


def unmatched_responses_request_additional_info(nino, transaction_id):
    logger.info(
        f'Requesting additional data for unmatched record", "nino": "{nino}", "transaction_id": "{transaction_id}')

    ireland_additional_data = get_additional_record_data(
        nino,
        transaction_id,
        args.ireland_parameter_name,
        "eu-west-1")

    london_additional_data = get_additional_record_data(
        nino,
        transaction_id,
        args.london_parameter_name,
        "eu-west-2")

    dynamodb_record_mismatch_record(ddb_client, ireland_additional_data, london_additional_data)


def dynamodb_record_mismatch_record(dynamodb, ireland_additional_data, london_additional_data):
    table = dynamodb.Table(args.ddb_record_mismatch_table)

    logger.info(
        f'Recording mismatch record into DynamoDB", "ddb_record_mismatch_table": "{args.ddb_record_mismatch_table}", '
        f'"nino": {ireland_additional_data["nino"]}')

    response = table.put_item(
        Item={
            'nino': ireland_additional_data["nino"],
            'transaction_id': ireland_additional_data["transaction_id"],
            'decrypted_take_home_pay': ireland_additional_data["take_home_pay"],
            "CONTRACT_ID_IRE": ireland_additional_data["ireland_additional_data"],
            "CONTRACT_ID_LDN": ireland_additional_data["ireland_additional_data"],
            "AP_FROM_IRE": ireland_additional_data["assessment_period_from_date"],
            "AP_TO_IRE": ireland_additional_data["assessment_period_to_date"],
            "AP_FROM_LDN": london_additional_data["assessment_period_from_date"],
            "AP_TO_LDN": london_additional_data["assessment_period_to_date"],
            "SUSPENDED_DATE_IRE": ireland_additional_data["suspended_date"],
            "SUSPENDED_DATE_LDN": london_additional_data["suspended_date"]
        }
    )


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
