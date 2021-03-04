#!/usr/bin/env python3

import unittest
from copy import deepcopy
from unittest import mock
from replayer_lambda.replayer import *

replayer_requests_method = "replayer_lambda.replayer.requests"
replayer_dates_method = "replayer_lambda.replayer.get_date_time_now"
app_json_header = "application/json"
expected_takehome_value = "rkLj7p2vTGD-XTLkm4P-ulLDM6Wtu1cjKDAcDr8dxjKu0w=="

lambda_client = mock.MagicMock()

"""Tests for the UC Export to Crown Controller Lambda."""

original_data = {
    "claimantFound": True,
    "assessmentPeriod": [
        {
            "fromDate": "20280301",
            "toDate": "20280331",
            "amount": {
                "keyId": "a",
                "takeHomePay": "1.23",
                "cipherTextBlob": "AQIDAHgQyXAXxSvKZWr5lmknNGdf6xcDAe9LpDG9V2tYEZy0uAEtFEdSOypakMgH05OAWwlUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMKcY_AKlKGKh2lM5aAgEQgDtElbx3A8ErRc9XB_scoHc5-Z9LWyqW1221o3K6JxQiGzNCjvM0K2cTGha11Jl-QbWlbaC3Fhfd7AqI7Q==",
            },
        },
        {
            "fromDate": "20280201",
            "toDate": "20280228",
            "amount": {
                "keyId": "a",
                "takeHomePay": "12.34",
                "cipherTextBlob": "AQIDAHgQyXAXxSvKZWr5lmknNGdf6xcDAe9LpDG9V2tYEZy0uAEtFEdSOypakMgH05OAWwlUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMKcY_AKlKGKh2lM5aAgEQgDtElbx3A8ErRc9XB_scoHc5-Z9LWyqW1221o3K6JxQiGzNCjvM0K2cTGha11Jl-QbWlbaC3Fhfd7AqI7Q==",
            },
        },
        {
            "fromDate": "20280101",
            "toDate": "20280131",
            "amount": {
                "keyId": "a",
                "takeHomePay": "123.45",
                "cipherTextBlob": "AQIDAHgQyXAXxSvKZWr5lmknNGdf6xcDAe9LpDG9V2tYEZy0uAEtFEdSOypakMgH05OAWwlUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMKcY_AKlKGKh2lM5aAgEQgDtElbx3A8ErRc9XB_scoHc5-Z9LWyqW1221o3K6JxQiGzNCjvM0K2cTGha11Jl-QbWlbaC3Fhfd7AqI7Q==",
            },
        },
    ],
}

request_parameters = {
    "nino": "AA123456A",
    "transactionId": "42",
    "fromDate": "20200101",
    "toDate": "20210101",
}


class TestReplayer(unittest.TestCase):
    def test_replay_original_request(self):
        with mock.patch(replayer_requests_method) as request_mock:
            with mock.patch(replayer_dates_method) as mock_time:
                with mock.patch("replayer_lambda.replayer.logger"):
                    data = """
                    {
                      "claimantFound": true,
                      "assessmentPeriod": [
                        {
                          "fromDate": "20280301",
                          "toDate": "20280331",
                          "amount": {
                            "keyId": "arn:aws:kms:eu-west-1:123456789022:key/this-needs-changing",
                            "takeHomePay": "rkLj7p2vTGD-XTLkm4P-ulLDM6Wtu1cjKDAcDr8dxjKu0w==",
                            "cipherTextBlob": "AQIDAHgQyXAXxSvKZWr5lmknNGdf6xcDAe9LpDG9V2tYEZy0uAEtFEdSOypakMgH05OAWwlUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMKcY_AKlKGKh2lM5aAgEQgDtElbx3A8ErRc9XB_scoHc5-Z9LWyqW1221o3K6JxQiGzNCjvM0K2cTGha11Jl-QbWlbaC3Fhfd7AqI7Q=="
                          }
                        }
                      ]
                    }
                    """
                    post_return_value = mock.Mock()
                    post_return_value.status_code = 200
                    post_return_value.text = data
                    request_mock.post.return_value = post_return_value
                    mock_time.return_value = "20200113T130000"

                    request_auth = mock.MagicMock()
                    args = mock.MagicMock()

                    args.hostname = "api.dev.gov.uk"
                    args.api_hostname = "api.dev.gov.uk"

                    headers = {
                        "Content-Type": app_json_header,
                        "X-Amz-Date": "20200113T130000",
                    }

                    result = replay_original_request(
                        request_auth, request_parameters, args
                    )

                    request_mock.post.assert_called_once_with(
                        f"https://{args.api_hostname}/ucfs-claimant/v1/getAwardDetails",
                        data="nino=AA123456A&transactionId=42&fromDate=20200101&toDate=20210101",
                        auth=request_auth,
                        headers=headers,
                    )

                    self.assertEqual(
                        expected_takehome_value,
                        result["assessmentPeriod"][0]["amount"]["takeHomePay"],
                    )
                    self.assertTrue(result["claimantFound"])

    def test_replay_original_request_with_missing_dates(self):
        with mock.patch(replayer_requests_method) as request_mock:
            with mock.patch(replayer_dates_method) as mock_time:
                with mock.patch("replayer_lambda.replayer.logger"):
                    request_parameters_copy = deepcopy(request_parameters)

                    # Removing date keys, the None arg stops a KeyError being raised
                    request_parameters_copy.pop("fromDate", None)
                    request_parameters_copy.pop("toDate", None)

                    data = """
                    {
                      "claimantFound": true,
                      "assessmentPeriod": [
                        {
                          "amount": {
                            "keyId": "arn:aws:kms:eu-west-1:123456789022:key/this-needs-changing",
                            "takeHomePay": "rkLj7p2vTGD-XTLkm4P-ulLDM6Wtu1cjKDAcDr8dxjKu0w==",
                            "cipherTextBlob": "AQIDAHgQyXAXxSvKZWr5lmknNGdf6xcDAe9LpDG9V2tYEZy0uAEtFEdSOypakMgH05OAWwlUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMKcY_AKlKGKh2lM5aAgEQgDtElbx3A8ErRc9XB_scoHc5-Z9LWyqW1221o3K6JxQiGzNCjvM0K2cTGha11Jl-QbWlbaC3Fhfd7AqI7Q=="
                          }
                        }
                      ]
                    }
                    """
                    post_return_value = mock.Mock()
                    post_return_value.status_code = 200
                    post_return_value.text = data
                    request_mock.post.return_value = post_return_value
                    mock_time.return_value = "20200113T130000"

                    request_auth = mock.MagicMock()
                    args = mock.MagicMock()

                    args.hostname = "api.dev.gov.uk"
                    args.api_hostname = "api.dev.gov.uk"

                    headers = {
                        "Content-Type": app_json_header,
                        "X-Amz-Date": "20200113T130000",
                    }

                    result = replay_original_request(
                        request_auth, request_parameters_copy, args
                    )

                    request_mock.post.assert_called_once_with(
                        f"https://{args.api_hostname}/ucfs-claimant/v1/getAwardDetails",
                        data="nino=AA123456A&transactionId=42",
                        auth=request_auth,
                        headers=headers,
                    )

                    self.assertEqual(
                        expected_takehome_value,
                        result["assessmentPeriod"][0]["amount"]["takeHomePay"],
                    )
                    self.assertTrue(result["claimantFound"])

                    self.assertNotIn("fromDate", result["assessmentPeriod"][0].keys())
                    self.assertNotIn("toDate", result["assessmentPeriod"][0].keys())

    def test_replay_original_request_with_empty_dates(self):
        with mock.patch(replayer_requests_method) as request_mock:
            with mock.patch(replayer_dates_method) as mock_time:
                with mock.patch("replayer_lambda.replayer.logger"):
                    request_parameters_copy = deepcopy(request_parameters)

                    # Removing date keys, the None arg stops a KeyError being raised
                    request_parameters_copy["fromDate"] = None
                    request_parameters_copy["toDate"] = None

                    data = """
                    {
                      "claimantFound": true,
                      "assessmentPeriod": [
                        {
                          "amount": {
                            "keyId": "arn:aws:kms:eu-west-1:123456789022:key/this-needs-changing",
                            "takeHomePay": "rkLj7p2vTGD-XTLkm4P-ulLDM6Wtu1cjKDAcDr8dxjKu0w==",
                            "cipherTextBlob": "AQIDAHgQyXAXxSvKZWr5lmknNGdf6xcDAe9LpDG9V2tYEZy0uAEtFEdSOypakMgH05OAWwlUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMKcY_AKlKGKh2lM5aAgEQgDtElbx3A8ErRc9XB_scoHc5-Z9LWyqW1221o3K6JxQiGzNCjvM0K2cTGha11Jl-QbWlbaC3Fhfd7AqI7Q=="
                          }
                        }
                      ]
                    }
                    """
                    post_return_value = mock.Mock()
                    post_return_value.status_code = 200
                    post_return_value.text = data
                    request_mock.post.return_value = post_return_value
                    mock_time.return_value = "20200113T130000"

                    request_auth = mock.MagicMock()
                    args = mock.MagicMock()

                    args.hostname = "api.dev.gov.uk"
                    args.api_hostname = "api.dev.gov.uk"

                    headers = {
                        "Content-Type": app_json_header,
                        "X-Amz-Date": "20200113T130000",
                    }

                    result = replay_original_request(
                        request_auth, request_parameters_copy, args
                    )

                    request_mock.post.assert_called_once_with(
                        f"https://{args.api_hostname}/ucfs-claimant/v1/getAwardDetails",
                        data="nino=AA123456A&transactionId=42",
                        auth=request_auth,
                        headers=headers,
                    )

                    self.assertEqual(
                        expected_takehome_value,
                        result["assessmentPeriod"][0]["amount"]["takeHomePay"],
                    )
                    self.assertTrue(result["claimantFound"])

                    self.assertNotIn("fromDate", result["assessmentPeriod"][0].keys())
                    self.assertNotIn("toDate", result["assessmentPeriod"][0].keys())

    def test_compare_responses_happy_path(self):
        # Copying & leaving unchanged for happy comparison
        actual_data = deepcopy(original_data)

        with mock.patch("replayer_lambda.replayer.logger") as mock_logger:
            with mock.patch("replayer_lambda.replayer.args") as mock_args:
                with mock.patch(
                    "replayer_lambda.replayer.forward_to_mismatch_handler"
                ) as mock_forward_func:
                    result = compare_responses(
                        original_data, actual_data, request_parameters, lambda_client
                    )

                    mock_logger.info.assert_any_call(
                        'Suspended date is not expected and not present in either original or replayed response", '
                        '"status": "match", '
                        f'"nino": "{request_parameters.get("nino")}", '
                        f'"transaction_id": "{request_parameters.get("transactionId")}", '
                        f'"from_date": "{request_parameters.get("fromDate")}", '
                        f'"to_date": "{request_parameters.get("toDate")}'
                    )

                    mock_logger.info.assert_any_call(
                        f'Comparing responses", '
                        f'"nino": "{request_parameters.get("nino")}", '
                        f'"transaction_id": "{request_parameters.get("transactionId")}", '
                        f'"from_date": "{request_parameters.get("fromDate")}", '
                        f'"to_date": "{request_parameters.get("toDate")}'
                    )

                    for record in original_data.get("assessmentPeriod", []):
                        mock_logger.info.assert_any_call(
                            f'Match for assessment period", "status": "match", '
                            f'"nino": "{request_parameters.get("nino")}", '
                            f'"transaction_id": "{request_parameters.get("transactionId")}", '
                            f'"from_date": "{request_parameters["fromDate"]}", '
                            f'"to_date": "{request_parameters["toDate"]}'
                        )

                    self.assertTrue(result)

    def test_compare_responses_with_different_assessment_periods(self):
        # Copying & leaving unchanged for happy comparison
        actual_data = deepcopy(original_data)
        actual_data["assessmentPeriod"][-1]["amount"]["takeHomePay"] = "54.66"
        actual_data["assessmentPeriod"][-1]["toDate"] = "20210304"

        with mock.patch("replayer_lambda.replayer.logger") as mock_logger:
            with mock.patch("replayer_lambda.replayer.args") as mock_args:
                with mock.patch(
                    "replayer_lambda.replayer.forward_to_mismatch_handler"
                ) as mock_forward_func:
                    result = compare_responses(
                        original_data, actual_data, request_parameters, lambda_client
                    )

                    mock_logger.info.assert_any_call(
                        'Suspended date is not expected and not present in either original or replayed response", '
                        '"status": "match", '
                        f'"nino": "{request_parameters.get("nino")}", '
                        f'"transaction_id": "{request_parameters.get("transactionId")}", '
                        f'"from_date": "{request_parameters.get("fromDate")}", '
                        f'"to_date": "{request_parameters.get("toDate")}'
                    )

                    mock_logger.info.assert_any_call(
                        f'Comparing responses", '
                        f'"nino": "{request_parameters.get("nino")}", '
                        f'"transaction_id": "{request_parameters.get("transactionId")}", '
                        f'"from_date": "{request_parameters.get("fromDate")}", '
                        f'"to_date": "{request_parameters.get("toDate")}'
                    )

                    for record in original_data.get("assessmentPeriod", [])[:-1]:
                        mock_logger.info.assert_any_call(
                            f'Match for assessment period", "status": "match", '
                            f'"nino": "{request_parameters.get("nino")}", '
                            f'"transaction_id": "{request_parameters.get("transactionId")}", '
                            f'"from_date": "{request_parameters.get("fromDate")}", '
                            f'"to_date": "{request_parameters.get("toDate")}'
                        )

                    original_record = original_data.get("assessmentPeriod")[-1]
                    mock_logger.info.assert_any_call(
                        f'No match for original response assessment period in replayed assessment period. ", '
                        f'"Forwarding to mismatch handler", "status": "miss", '
                        f'"nino": "{request_parameters.get("nino")}", '
                        f'"transaction_id": "{request_parameters["transactionId"]}", '
                        f'"from_date": "{request_parameters.get("fromDate")}", '
                        f'"to_date": "{request_parameters.get("toDate")}'
                    )

                    mock_forward_func.assert_any_call(
                        request_parameters["nino"],
                        request_parameters["transactionId"],
                        original_record["amount"]["takeHomePay"],
                        lambda_client,
                        mock_args,
                    )

                    actual_record = actual_data.get("assessmentPeriod")[-1]
                    mock_logger.info.assert_any_call(
                        f'No match for replayed assessment period in original response assessment period.", '
                        f'"Forwarding to mismatch handler", "status": "miss", '
                        f'"nino": "{request_parameters.get("nino")}", '
                        f'"transaction_id": "{request_parameters.get("transactionId")}", '
                        f'"from_date": "{request_parameters.get("fromDate")}", '
                        f'"to_date": "{request_parameters.get("toDate")}'
                    )

                    mock_forward_func.assert_called_with(
                        request_parameters["nino"],
                        request_parameters["transactionId"],
                        actual_record["amount"]["takeHomePay"],
                        lambda_client,
                        mock_args,
                    )

                    self.assertFalse(result)

    def test_compare_responses_with_suspended_date_present_in_both(self):
        # Making copies of the original data as to not change it
        original_data_copy = deepcopy(original_data)
        actual_data = deepcopy(original_data)

        original_data_copy["suspendedDate"] = "1234"
        actual_data["suspendedDate"] = "1234"

        with mock.patch("replayer_lambda.replayer.logger") as mock_logger:
            result = compare_responses(
                original_data_copy, actual_data, request_parameters, lambda_client
            )

            mock_logger.info.assert_any_call(
                'Suspended date is a match", "status": "match", '
                f'"nino": "{request_parameters.get("nino")}", '
                f'"transaction_id": "{request_parameters.get("transactionId")}", '
                f'"from_date": "{request_parameters.get("fromDate")}", '
                f'"to_date": "{request_parameters.get("toDate")}'
            )

            mock_logger.info.assert_any_call(
                f'Comparing responses", '
                f'"nino": "{request_parameters.get("nino")}", '
                f'"transaction_id": "{request_parameters.get("transactionId")}", '
                f'"from_date": "{request_parameters.get("fromDate")}", '
                f'"to_date": "{request_parameters.get("toDate")}'
            )

            for record in original_data.get("assessmentPeriod", []):
                mock_logger.info.assert_any_call(
                    f'Match for assessment period", "status": "match", '
                    f'"nino": "{request_parameters.get("nino")}", '
                    f'"transaction_id": "{request_parameters.get("transactionId")}", '
                    f'"from_date": "{request_parameters.get("fromDate")}", '
                    f'"to_date": "{request_parameters.get("toDate")}'
                )

            self.assertTrue(result)

    def test_compare_responses_with_suspended_date_in_original_only(self):
        # Making copies of the original data as to not change it
        original_data_copy = deepcopy(original_data)
        actual_data = deepcopy(original_data)

        original_data_copy["suspendedDate"] = "1234"

        with mock.patch("replayer_lambda.replayer.logger") as mock_logger:
            with mock.patch("replayer_lambda.replayer.args") as mock_args:
                with mock.patch(
                    "replayer_lambda.replayer.forward_to_mismatch_handler"
                ) as mock_forward_func:
                    result = compare_responses(
                        original_data_copy,
                        actual_data,
                        request_parameters,
                        lambda_client,
                    )

                    mock_logger.info.assert_any_call(
                        'Suspended date expected but does not match or was not found in replayed response.", '
                        '"Forwarding to mismatch handler", "status": "miss", '
                        f'"nino": "{request_parameters.get("nino")}", '
                        f'"transaction_id": "{request_parameters.get("transactionId")}", '
                        f'"from_date": "{request_parameters.get("fromDate")}", '
                        f'"to_date": "{request_parameters.get("toDate")}'
                    )

                    mock_forward_func.assert_called_with(
                        request_parameters["nino"],
                        request_parameters["transactionId"],
                        "",
                        lambda_client,
                        mock_args,
                    )

                    mock_logger.info.assert_any_call(
                        f'Comparing responses", '
                        f'"nino": "{request_parameters.get("nino")}", '
                        f'"transaction_id": "{request_parameters.get("transactionId")}", '
                        f'"from_date": "{request_parameters.get("fromDate")}", '
                        f'"to_date": "{request_parameters.get("toDate")}'
                    )

                    for record in original_data.get("assessmentPeriod", []):
                        mock_logger.info.assert_any_call(
                            f'Match for assessment period", "status": "match", '
                            f'"nino": "{request_parameters.get("nino")}", '
                            f'"transaction_id": "{request_parameters.get("transactionId")}", '
                            f'"from_date": "{request_parameters["fromDate"]}", '
                            f'"to_date": "{request_parameters["toDate"]}'
                        )

                    self.assertFalse(result)

    def test_compare_responses_with_suspendedDate_present_in_both_but_mismatch(self):
        # Making copies of the original data as to not change it
        original_data_copy = deepcopy(original_data)
        actual_data = deepcopy(original_data)

        original_data_copy["suspendedDate"] = "1234"
        actual_data["suspendedDate"] = "4321"

        with mock.patch("replayer_lambda.replayer.logger") as mock_logger:
            with mock.patch("replayer_lambda.replayer.args") as mock_args:
                with mock.patch(
                    "replayer_lambda.replayer.forward_to_mismatch_handler"
                ) as mock_forward_func:
                    result = compare_responses(
                        original_data_copy,
                        actual_data,
                        request_parameters,
                        lambda_client,
                    )

                    mock_logger.info.assert_any_call(
                        'Suspended date expected but does not match or was not found in replayed response.", '
                        '"Forwarding to mismatch handler", "status": "miss", '
                        f'"nino": "{request_parameters.get("nino")}", '
                        f'"transaction_id": "{request_parameters.get("transactionId")}", '
                        f'"from_date": "{request_parameters.get("fromDate")}", '
                        f'"to_date": "{request_parameters.get("toDate")}'
                    )

                    mock_forward_func.assert_called_with(
                        request_parameters["nino"],
                        request_parameters["transactionId"],
                        "",
                        lambda_client,
                        mock_args,
                    )

                    mock_logger.info.assert_any_call(
                        f'Comparing responses", '
                        f'"nino": "{request_parameters.get("nino")}", '
                        f'"transaction_id": "{request_parameters.get("transactionId")}", '
                        f'"from_date": "{request_parameters.get("fromDate")}", '
                        f'"to_date": "{request_parameters.get("toDate")}'
                    )

                    for record in original_data.get("assessmentPeriod", []):
                        mock_logger.info.assert_any_call(
                            f'Match for assessment period", "status": "match", '
                            f'"nino": "{request_parameters.get("nino")}", '
                            f'"transaction_id": "{request_parameters.get("transactionId")}", '
                            f'"from_date": "{request_parameters["fromDate"]}", '
                            f'"to_date": "{request_parameters["toDate"]}'
                        )

                    self.assertFalse(result)

    def test_compare_responses_with_claimantFound_mismatch(self):
        # Making copies of the original data as to not change it
        actual_data = deepcopy(original_data)

        actual_data["claimantFound"] = False

        with mock.patch("replayer_lambda.replayer.logger") as mock_logger:
            with mock.patch("replayer_lambda.replayer.args") as mock_args:
                with mock.patch(
                    "replayer_lambda.replayer.forward_to_mismatch_handler"
                ) as mock_forward_func:
                    result = compare_responses(
                        original_data, actual_data, request_parameters, lambda_client
                    )

                    mock_logger.info.assert_any_call(
                        f'Claimant found does not match, ", '
                        f'"expected {original_data["claimantFound"]} from replayed response but got {actual_data["claimantFound"]}.", '
                        f'"Forwarding to mismatch handler", "status": "miss", '
                        f'"nino": "{request_parameters.get("nino")}", '
                        f'"transaction_id": "{request_parameters.get("transactionId")}", '
                        f'"from_date": "{request_parameters["fromDate"]}", '
                        f'"to_date": "{request_parameters["toDate"]}'
                    )

                    mock_forward_func.assert_called_with(
                        request_parameters["nino"],
                        request_parameters["transactionId"],
                        "",
                        lambda_client,
                        mock_args,
                    )

                    mock_logger.info.assert_any_call(
                        'Suspended date is not expected and not present in either original or replayed response", '
                        '"status": "match", '
                        f'"nino": "{request_parameters.get("nino")}", '
                        f'"transaction_id": "{request_parameters.get("transactionId")}", '
                        f'"from_date": "{request_parameters["fromDate"]}", '
                        f'"to_date": "{request_parameters["toDate"]}'
                    )

                    mock_logger.info.assert_any_call(
                        f'Comparing responses", '
                        f'"nino": "{request_parameters.get("nino")}", '
                        f'"transaction_id": "{request_parameters.get("transactionId")}", '
                        f'"from_date": "{request_parameters.get("fromDate")}", '
                        f'"to_date": "{request_parameters.get("toDate")}'
                    )

                    for record in original_data.get("assessmentPeriod", []):
                        mock_logger.info.assert_called_with(
                            f'Match for assessment period", "status": "match", '
                            f'"nino": "{request_parameters.get("nino")}", '
                            f'"transaction_id": "{request_parameters.get("transactionId")}", '
                            f'"from_date": "{request_parameters["fromDate"]}", '
                            f'"to_date": "{request_parameters["toDate"]}'
                        )

                    self.assertFalse(result)


    def test_forward_mismatch_handler_with_mismatch_data(self):
        args = mock.MagicMock()

        args.mismatch_lambda_name = "mismatch_handler"
        args.mismatch_lambda_region = "eu-west-1"

        nino = "AA123456B"
        transaction_id = "23"
        take_home_pay = "123.45"

        lambda_client = mock.MagicMock()
        lambda_client.invoke = mock.MagicMock()
        lambda_client.invoke.return_value = "Test return"

        lambda_payload = json.dumps(
            {
                "nino": nino,
                "transaction_id": transaction_id,
                "take_home_pay": take_home_pay,
            }
        )

        with mock.patch("replayer_lambda.replayer.logger") as mock_logger:
            forward_to_mismatch_handler(
                nino, transaction_id, take_home_pay, lambda_client, args
            )

            mock_logger.info.assert_called_with(
                'Invoked lambda successfully", "response": "Test return'
            )

            lambda_client.invoke.assert_called_with(
                FunctionName=args.mismatch_lambda_name,
                InvocationType="Event",
                Payload=lambda_payload,
            )

    def test_forward_mismatch_handler_catches_lambda_invocation_exceptions(self):
        args = mock.MagicMock()

        args.mismatch_lambda_name = "mismatch_handler"
        args.mismatch_lambda_region = "eu-west-1"

        nino = "AA123456C"
        transaction_id = "27"
        take_home_pay = "124.45"

        lambda_client_mock = mock.MagicMock()
        lambda_client_mock.invoke = mock.MagicMock()
        lambda_client_mock.invoke.side_effect = Exception("Test exception")

        lambda_payload = json.dumps(
            {
                "nino": nino,
                "transaction_id": transaction_id,
                "take_home_pay": take_home_pay,
            }
        )

        with mock.patch("replayer_lambda.replayer.logger") as mock_logger:
            with self.assertRaises(Exception):
                forward_to_mismatch_handler(
                    nino, transaction_id, take_home_pay, lambda_client, args
                )

                lambda_client_mock.invoke.assert_called_with(
                    args.mismatch_lambda_name, "Event", lambda_payload
                )

                mock_logger.info.assert_any_call(
                    f'Failed to invoke lambda", "exception": "Test exception'
                )
