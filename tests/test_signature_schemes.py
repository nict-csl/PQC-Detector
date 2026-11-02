import sys

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import summary  # noqa: E402

MAPPINGS_DIR = REPO_ROOT / "mappings"


def test_load_signature_schemes_mapping():
    _, _, _, schemes = summary.load_mappings(MAPPINGS_DIR)
    assert schemes[0x0904]["name"] == "mldsa44"
    assert schemes[0x0904]["is_pqc"] is True
    assert schemes[0x0906]["is_pqc"] is True
    assert schemes[0x0911]["is_pqc"] is True  # slh-dsa
    # a classical scheme must not be flagged as PQC
    assert schemes[0x0403]["is_pqc"] is False


def test_is_pqc_signature_algorithms():
    _, _, _, schemes = summary.load_mappings(MAPPINGS_DIR)
    assert summary.is_pqc_signature_algorithms("0x0905", schemes) is True
    assert summary.is_pqc_signature_algorithms("0x0911", schemes) is True
    assert summary.is_pqc_signature_algorithms("0x0403,0x0804", schemes) is False
    assert summary.is_pqc_signature_algorithms("0x0403,0x0904", schemes) is True
    assert summary.is_pqc_signature_algorithms("", schemes) is False


def test_clienthello_counted_pqc_from_signature_algorithms():
    groups, cipher, proto, schemes = summary.load_mappings(MAPPINGS_DIR)
    # ClientHello with only a classical group (secp256r1, 0x0017) but a PQC signature scheme (mldsa44).
    rows = [
        (
            {
                "Frame": "1",
                "Src": "1.1.1.1",
                "SrcPort": "5",
                "Dst": "2.2.2.2",
                "DstPort": "443",
                "Proto": "TLS",
                "SupportedGroups": "0x0017",
                "SignatureAlgorithms": "0x0904",
                "ServerName": "example",
            },
            "clienthello",
        ),
    ]
    stats = summary.calculate_statistics(iter(rows), groups, cipher, proto, schemes)
    assert stats["clienthello_total"] == 1
    # the key exchange group is classical, so the group-based PQC counter stays zero
    assert stats["clienthello_pqc"] == 0
    # the signature scheme is post-quantum, so the signature PQC counter is one
    assert stats["clienthello_pqc_sig"] == 1
