from stoa_server.job_authorization import target_matches_scope


def test_target_matching_supports_exact_host_and_cidr() -> None:
    assert target_matches_scope("127.0.0.1", "127.0.0.0/8")
    assert not target_matches_scope("8.8.8.8", "127.0.0.0/8")
    assert target_matches_scope("lab.internal", "LAB.INTERNAL")
    assert not target_matches_scope("other.internal", "lab.internal")


def test_url_scope_requires_matching_origin_and_path_prefix() -> None:
    assert target_matches_scope("https://example.test/app/status", "https://example.test/app")
    assert not target_matches_scope("http://example.test/app", "https://example.test/app")
    assert not target_matches_scope("https://evil.test/app", "https://example.test/app")
