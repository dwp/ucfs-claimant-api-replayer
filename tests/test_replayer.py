import unittest

@Test
#!/usr/bin/env python3

"""Tests for the UC Export to Crown Controller Lambda."""
import json
import pytest
import unittest
from src import replayer

class TestReplayer(unittest.TestCase):

    def test_that_compare_responses_validates_all_fields(self):
        original_request =
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
                },
                {
                    "fromDate": "20280201",
                    "toDate": "20280228",
                    "amount": {
                        "keyId": "arn:aws:kms:eu-west-1:475593055014:key/08db5e60-156c-4e41-b61f-60a3556efd7e",
                        "takeHomePay": "HfiM34q-BM_YDjh7ujZAZHpk9h7wZaP0HDuUuxnSBVwU3A==",
                        "cipherTextBlob": "AQIDAHgQyXAXxSvKZWr5lmknNGdf6xcDAe9LpDG9V2tYEZy0uAEtFEdSOypakMgH05OAWwlUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMKcY_AKlKGKh2lM5aAgEQgDtElbx3A8ErRc9XB_scoHc5-Z9LWyqW1221o3K6JxQiGzNCjvM0K2cTGha11Jl-QbWlbaC3Fhfd7AqI7Q=="
                    }
                },
                {
                    "fromDate": "20280101",
                    "toDate": "20280131",
                    "amount": {
                        "keyId": "arn:aws:kms:eu-west-1:475593055014:key/08db5e60-156c-4e41-b61f-60a3556efd7e",
                        "takeHomePay": "UMqmIMl5oHr5vn8ie-w1vmQUYv_mrUv-wcdKgsSy0e9Tsg==",
                        "cipherTextBlob": "AQIDAHgQyXAXxSvKZWr5lmknNGdf6xcDAe9LpDG9V2tYEZy0uAEtFEdSOypakMgH05OAWwlUAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMKcY_AKlKGKh2lM5aAgEQgDtElbx3A8ErRc9XB_scoHc5-Z9LWyqW1221o3K6JxQiGzNCjvM0K2cTGha11Jl-QbWlbaC3Fhfd7AqI7Q=="
                    }
                }
            ]
        }
