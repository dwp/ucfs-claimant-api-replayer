#!/usr/bin/env python3

import unittest
from unittest import mock
from src.replayer import *

"""Tests for the UC Export to Crown Controller Lambda."""


class TestReplayer(unittest.TestCase):
    def test_replay_original_request(self):
        with mock.patch("src.replayer.requests") as request_mock:
            with mock.patch("src.replayer.logger") as logger:

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

                request_parameters = {
                    "nino": "AA123456A",
                    "transactionId": "42",
                    "fromDate": "20200101",
                    "toDate": "20210101",
                }

                headers = {
                    "Content-Type": "application/json",
                    "X-Amz-Date": "20200113T130000",
                }

                result = replay_original_request(
                    request_auth, request_parameters, "20200113T130000", args
                )

                request_mock.post.assert_called_once_with(
                    f"https://{args.api_hostname}/ucfs-claimant/v2/getAwardDetails",
                    data="nino=AA123456A&transactionId=42&fromDate=20200101&toDo=20210101",
                    auth=request_auth,
                    headers=headers,
                )

                expected_takehome = "rkLj7p2vTGD-XTLkm4P-ulLDM6Wtu1cjKDAcDr8dxjKu0w=="
                expected_claimantfound = True

                print(result)
                self.assertEqual(
                    expected_takehome,
                    result["assessmentPeriod"][0]["amount"]["takeHomePay"],
                )
                self.assertEqual(expected_claimantfound, result["claimantFound"])
