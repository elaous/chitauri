import pytest

from app.import_utils import group_by_os_id, parse_csv_rows, parse_json_rows
from app.storage.base import ConfigValidationError, VerifiedBootKeyData

SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA2 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


def test_verified_boot_key_data_normalizes_case():
    key = VerifiedBootKeyData(verified_boot_key_sha256=SHA.upper())
    assert key.verified_boot_key_sha256 == SHA


def test_verified_boot_key_data_rejects_bad_hash():
    with pytest.raises(ConfigValidationError):
        VerifiedBootKeyData(verified_boot_key_sha256="not-a-hash")


def test_parse_json_rows_single():
    rows = parse_json_rows([{"os_id": "grapheneos", "verified_boot_key_sha256": SHA}])
    assert rows == [("grapheneos", VerifiedBootKeyData(verified_boot_key_sha256=SHA))]


def test_parse_json_rows_requires_os_id_or_default():
    with pytest.raises(ConfigValidationError):
        parse_json_rows([{"verified_boot_key_sha256": SHA}])
    rows = parse_json_rows([{"verified_boot_key_sha256": SHA}], default_os_id="grapheneos")
    assert rows[0][0] == "grapheneos"


def test_parse_csv_rows_with_os_id_column():
    text = f"os_id,device,release,verified_boot_key_sha256\ngrapheneos,Pixel 8,2026.09.01,{SHA}\n"
    rows = parse_csv_rows(text)
    assert len(rows) == 1
    os_id, key = rows[0]
    assert os_id == "grapheneos"
    assert key.device == "Pixel 8"
    assert key.release == "2026.09.01"
    assert key.verified_boot_key_sha256 == SHA


def test_parse_csv_rows_without_os_id_column_uses_default():
    text = f"device,release,verified_boot_key_sha256\nPixel 8,2026.09.01,{SHA}\n"
    rows = parse_csv_rows(text, default_os_id="grapheneos")
    assert rows[0][0] == "grapheneos"


def test_parse_csv_rows_missing_os_id_and_default_raises():
    text = f"device,release,verified_boot_key_sha256\nPixel 8,2026.09.01,{SHA}\n"
    with pytest.raises(ConfigValidationError):
        parse_csv_rows(text)


def test_parse_csv_rows_unknown_column_raises():
    text = "os_id,bogus_column\ngrapheneos,whatever\n"
    with pytest.raises(ConfigValidationError):
        parse_csv_rows(text)


def test_parse_csv_rows_empty_text_returns_empty():
    assert parse_csv_rows("") == []


def test_group_by_os_id():
    rows = [
        ("grapheneos", VerifiedBootKeyData(verified_boot_key_sha256=SHA)),
        ("grapheneos", VerifiedBootKeyData(verified_boot_key_sha256=SHA2)),
        ("stock_android", VerifiedBootKeyData(verified_boot_key_sha256=SHA)),
    ]
    grouped = group_by_os_id(rows)
    assert set(grouped) == {"grapheneos", "stock_android"}
    assert len(grouped["grapheneos"]) == 2
    assert len(grouped["stock_android"]) == 1
