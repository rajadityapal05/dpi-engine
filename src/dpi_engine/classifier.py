from dataclasses import dataclass


APPLICATION_DOMAINS = {
    "youtube": [
        "youtube.com",
        "youtu.be",
        "googlevideo.com",
        "ytimg.com"
    ],
    "tiktok": [
        "tiktok.com",
        "tiktokcdn.com"
    ],
    "netflix": [
        "netflix.com",
        "nflxvideo.net",
        "nflximg.net"
    ],
    "google": [
        "google.com",
        "googleapis.com",
        "gstatic.com"
    ],
    "github": [
        "github.com",
        "githubusercontent.com"
    ],
    "reddit": [
        "reddit.com",
        "redd.it",
        "redditmedia.com"
    ],
    "facebook": [
        "facebook.com",
        "fbcdn.net",
        "fb.com"
    ],
    "instagram": [
        "instagram.com",
        "cdninstagram.com"
    ]
}


@dataclass(frozen=True)
class ClassificationResult:
    application: str | None
    confidence: float
    evidence: str


def domain_matches(domain, candidate):
    domain = domain.lower().rstrip(".")
    candidate = candidate.lower().rstrip(".")

    return (
        domain == candidate
        or domain.endswith("." + candidate)
    )


class ApplicationClassifier:

    @staticmethod
    def classify(domain):
        if not domain:
            return None

        for application, domains in APPLICATION_DOMAINS.items():
            for candidate in domains:
                if domain_matches(domain, candidate):
                    return application

        return "other"

    @staticmethod
    def classify_with_confidence(domain, source="domain"):
        application = ApplicationClassifier.classify(domain)

        if not application:
            return ClassificationResult(
                application=None,
                confidence=0.0,
                evidence="no domain detected"
            )

        if application == "other":
            return ClassificationResult(
                application="other",
                confidence=0.40,
                evidence=source
            )

        confidence_by_source = {
            "tls_sni": 0.95,
            "http_host": 0.95,
            "dns": 0.90,
            "domain": 0.85
        }

        return ClassificationResult(
            application=application,
            confidence=confidence_by_source.get(source, 0.85),
            evidence=source
        )
