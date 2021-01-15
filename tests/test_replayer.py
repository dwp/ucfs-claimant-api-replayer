#!/usr/bin/env python3

import unittest
from copy import deepcopy
from unittest import mock
from src.replayer import *

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
        with mock.patch("src.replayer.requests") as request_mock:
            with mock.patch("src.replayer.logger"):
                data = """
                {
                  "claimantFound": true,
                  "assessmentPeriod": [
                    {
                      "fromDate": "20280301",
                      "toDate": "20280331",
                      "amount": {
                        "keyId": "arn:aws:kms:eu-west-1:475593055014:key/08db5e60-156c-4e41-b61f-60a3556efd7e",
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

                request_auth = mock.MagicMock()
                args = mock.MagicMock()

                args.hostname = "api.dev.gov.uk"
                args.api_hostname = "api.dev.gov.uk"

                headers = {
                    "Content-Type": "application/json",
                    "X-Amz-Date": "20200113T130000",
                }

                result = replay_original_request(
                    request_auth, request_parameters, "20200113T130000", args
                )

                request_mock.post.assert_called_once_with(
                    f"https://{args.api_hostname}/ucfs-claimant/v2/getAwardDetails",
                    data="nino=AA123456A&transactionId=42&fromDate=20200101&toDate=20210101",
                    auth=request_auth,
                    headers=headers,
                )

                expected_takehome = "rkLj7p2vTGD-XTLkm4P-ulLDM6Wtu1cjKDAcDr8dxjKu0w=="

                self.assertEqual(
                    expected_takehome,
                    result["assessmentPeriod"][0]["amount"]["takeHomePay"],
                )
                self.assertTrue(result["claimantFound"])

    def test_compare_responses_happy_path(self):
        # Copying & leaving unchanged for happy comparison
        actual_data = original_data.copy()

        with mock.patch("src.replayer.logger") as mock_logger:
            result = compare_responses(original_data, actual_data, request_parameters)

            mock_logger.info.assert_any_call(
                'Suspended date is not expected and not present in either original or replayed response", '
                '"status": "match'
            )

            mock_logger.info.assert_any_call(
                f'Comparing responses", '
                f'"transaction_id": {request_parameters.get("transactionId")}, '
                f'"from_date": {request_parameters.get("fromDate")}, '
                f'"to_date": {request_parameters.get("toDate")}'
            )

            for record in original_data.get("assessmentPeriod", []):
                mock_logger.info.assert_any_call(
                    f'Match for assessment period", "status": "match", '
                    f'"transaction_id": {request_parameters.get("transactionId")}, '
                    f'"AP_from_date": {record["fromDate"]},'
                    f'"AP_to_date": {record["toDate"]}'
                )

            self.assertTrue(result)

    def test_compare_responses_with_different_assessment_periods(self):
        # Copying & leaving unchanged for happy comparison
        actual_data = deepcopy(original_data)
        actual_data["assessmentPeriod"][-1]["amount"]["takeHomePay"] = "54.66"

        with mock.patch("src.replayer.logger") as mock_logger:
            result = compare_responses(original_data, actual_data, request_parameters)

            mock_logger.info.assert_any_call(
                'Suspended date is not expected and not present in either original or replayed response", '
                '"status": "match'
            )

            mock_logger.info.assert_any_call(
                f'Comparing responses", '
                f'"transaction_id": {request_parameters.get("transactionId")}, '
                f'"from_date": {request_parameters.get("fromDate")}, '
                f'"to_date": {request_parameters.get("toDate")}'
            )

            for record in original_data.get("assessmentPeriod", [])[:-1]:
                mock_logger.info.assert_any_call(
                    f'Match for assessment period", "status": "match", '
                    f'"transaction_id": {request_parameters.get("transactionId")}, '
                    f'"AP_from_date": {record["fromDate"]},'
                    f'"AP_to_date": {record["toDate"]}'
                )

            record = original_data.get("assessmentPeriod")[-1]
            mock_logger.info.assert_any_call(
                f'No match for replayed assessment period in original response assessment period", "status": "miss", '
                f'"transaction_id": {request_parameters["transactionId"]}, '
                f'"AP_from_date": {record["fromDate"]},'
                f'"AP_to_date": {record["toDate"]}'
            )

            record = actual_data.get("assessmentPeriod")[-1]
            mock_logger.info.assert_any_call(
                f'No match for replayed assessment period in original response assessment period", "status": "miss", '
                f'"transaction_id": {request_parameters["transactionId"]}, '
                f'"AP_from_date": {record["fromDate"]},'
                f'"AP_to_date": {record["toDate"]}'
            )

            self.assertFalse(result)

    def test_compare_responses_with_suspended_date_present_in_both(self):
        pass

    def test_compare_responses_with_suspended_date_in_original_only(self):
        pass

    def test_compare_responses_with_claimantFound_mismatch(self):
        pass
