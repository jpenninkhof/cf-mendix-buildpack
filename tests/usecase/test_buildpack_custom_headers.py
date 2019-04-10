import basetest
import requests
import json


class TestCaseBuildPackCustomHeaderConfig(basetest.BaseTest):
    def setUp(self):
        super().setUp()

    def _httpget(self):
        try:
            response = requests.get("https://" + self.app_name)
        except Exception as e:
            print("Failed to get request got {}".format(requests.status_code))
        return response

    def test_custom_header_settings(self):
        self.setUpCF(
            "sample-6.2.0.mda",
            env_vars={
                "X_FRAME_OPTIONS": "DENY",
                "HTTP_RESPONSE_HEADERS": json.dumps(
                    {
                        "X-Frame-Options": "SAMEORIGIN",
                        "X-Permitted-Cross-Domain-Policies": "by-content-type",
                        "Access-Control-Allow-Origin": "https://this.is.mydomain.nl",
                        "X-XSS-Protection": "1; report=https://domainwithnewstyle.tld.consultancy",
                        "X-Content-Type-Options": "nosniff",
                    }
                ),
            },
        )
        self.startApp()

        response = self._httpget()

        assert "SAMEORIGIN" in response.headers["x-frame-options"]
        assert (
            "https://this.is.mydomain.nl"
            in response.headers["access-control-allow-origin"]
        )
        assert "nosniff" in response.headers["x-content-type-options"]
        assert (
            "by-content-type"
            in response.headers["x-permitted-cross-domain-policies"]
        )
        assert (
            "1; report=https://domainwithnewstyle.tld.consultancy"
            in response.headers["x-xss-protection"]
        )
