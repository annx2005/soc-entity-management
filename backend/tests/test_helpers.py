from app.normalization.helpers import parse_first_ip, parse_sha256, process_name_from_path


def test_process_name_from_windows_path() -> None:
    assert process_name_from_path(r"C:\Windows\System32\curl.exe") == "curl.exe"


def test_parse_sha256_from_sysmon_hashes() -> None:
    hashes = "MD5=abc,SHA256=642a07eeea4d3132426e673fb3c88be8cead3d03ca1f019c7e7d0000ed2122be,IMPHASH=def"
    assert parse_sha256(hashes) == "642A07EEEA4D3132426E673FB3C88BE8CEAD3D03CA1F019C7E7D0000ED2122BE"


def test_parse_first_ip_from_dns_results() -> None:
    assert parse_first_ip("type: 5 example.com;::ffff:140.82.113.21;") == "140.82.113.21"
