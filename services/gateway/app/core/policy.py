import yaml

from app.core.canonical import sha256_hex

FILES = ("rules.yaml", "templates.yaml", "users.yaml")


class Policy:
    def __init__(self, policy_dir):
        self.rules = yaml.safe_load((policy_dir / "rules.yaml").read_text())
        self.templates = yaml.safe_load((policy_dir / "templates.yaml").read_text())
        self.hash = sha256_hex("".join(sha256_hex((policy_dir / f).read_bytes()) for f in FILES))
