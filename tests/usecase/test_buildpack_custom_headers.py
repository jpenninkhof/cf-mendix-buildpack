import basetest
import requests


class TestCaseBuildPackCustomHeaderConfig(basetest.BaseTest):

    def setUp(self):
        super().setUp()

    def _httpget(self):
        try:
            response = requests.get("https://" + self.app_name)
        except Exception as e:
            print(
                "Failed to get request got {}".format(requests.status_code)
            )
        return response

    def test_custom_header_settings(self):
        self.setUpCF(
            "sample-6.2.0.mda",
            env_vars={
                "X_FRAME_OPTIONS": "deny",
                "HTTP_RESPONSE_HEADERS": '{"X-Permitted-Cross-Domain-Policies": "by-content-type","Access-Control-Allow-Origin": "https://this.is.mydomain.nl","X-XSS-Protection": "1; report=https://domainwithnewstyle.tld.consultancy","X-Content-Type-Options": "nosniff"}',  # noqa: E501
                },
            )
        self.startApp()

        response = self._httpget()

        assert "deny" in response.headers["X-Frame-Options"]
        assert "https://this.is.mydomain.nl" in response.headers["Access-Control-Allow-Origin"]
        assert "nosniff" in response.headers["X-Content-Type-Options"]
        assert "by-content-type" in response.headers["X-Permitted-Cross-Domain-Policies"]
        assert "1; report=https://domainwithnewstyle.tld.consultancy" in response.headers["X-XSS-Protection"]
