import json

from tls_scanner.scanners import WizScanner


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return json.dumps({
            "result": {
                "reachable": True,
                "certificate_valid": True,
                "hostname_verified": True,
                "tls_version": "TLSv1.3",
                "cipher": "TLS_AES_128_GCM_SHA256",
            }
        }).encode()


def test_wiz_scanner_maps_normalized_result(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout: FakeResponse(),
    )

    result = WizScanner("https://wiz.example").scan("example.com", 5)

    assert result.endpoint == "example.com"
    assert result.reachable is True
    assert result.tls_version == "TLSv1.3"
    assert result.cipher == "TLS_AES_128_GCM_SHA256"
