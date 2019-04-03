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
                "HTTP_RESPONSE_HEADERS": '{"X-Frame-Options": "SAMEORIGIN"}',
                "X_FRAME_OPTIONS": "deny"
                },
            )
        self.startApp()

        response = self._httpget()

        assert "deny" in response.headers["X-Frame-Options"]
