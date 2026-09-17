from dpr.discovery.detect import detect
from dpr.walk import RepoIndex
from tests.reviews.helpers import write


def test_static_host_header_configs_are_detected(tmp_path):
    write(
        tmp_path, "web/staticwebapp.config.json", '{"globalHeaders": {"X-Frame-Options": "DENY"}}'
    )
    write(tmp_path, "site/firebase.json", '{"hosting": {"headers": []}}')
    write(tmp_path, "web/src/main.ts", "export {}\n")
    assert detect(RepoIndex(tmp_path)).header_config == ["web/staticwebapp.config.json"]
