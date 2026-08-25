from dataclasses import dataclass

KNOWN_CAA_TAGS = {"issue", "issuewild", "iodef"}


@dataclass(frozen=True)
class CAARecord:
    flags: int
    tag: str    # normalized lowercase
    value: str  # decoded UTF-8, errors="replace"

    @property
    def is_critical_unknown(self) -> bool:
        return bool(self.flags & 0x80) and self.tag not in KNOWN_CAA_TAGS

    def issuer_domain(self):
        """Return the issuer-domain-name from an issue/issuewild value,
        or None for non-issue tags. Per RFC 8659 section 4.2 the value is
        'issuer-domain-name [; parameters]'. An empty issuer-domain-name
        (value ';' or '') means no CA may issue."""
        if self.tag not in ("issue", "issuewild"):
            return None
        name = self.value.split(";", 1)[0].strip().lower()
        return name  # may be "" for deny-all

    def to_display(self) -> str:
        return f'{self.flags} {self.tag} "{self.value}"'
