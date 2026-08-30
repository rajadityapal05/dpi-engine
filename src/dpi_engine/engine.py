from .classifier import ApplicationClassifier
from .dns_extractor import DNSExtractor
from .flow_tracker import FlowTracker
from .packet_parser import PacketParser
from .rules import RuleManager
from .sni_extractor import SNIExtractor
from .tls_parser import TLSParser


class DPIEngine:

    def __init__(self, rule_manager=None):
        self.classifier = ApplicationClassifier()
        self.flow_tracker = FlowTracker()
        self.rules = rule_manager or RuleManager()

        self.total_packets = 0
        self.forwarded_packets = 0
        self.blocked_packets = 0

        self.application_stats = {}
        self.decision_stats = {
            "ALLOW": 0,
            "BLOCK": 0,
            "UNKNOWN": 0
        }

        self.total_bytes = 0

        self.last_domain = None
        self.last_application = None
        self.last_confidence = 0.0
        self.last_evidence = None

    def process_packet(self, packet):

        self.total_packets += 1

        packet_size = len(bytes(packet))
        self.total_bytes += packet_size

        parsed = PacketParser.parse(packet)

        if parsed is None:
            self.last_domain = None
            self.last_application = None
            self.last_confidence = 0.0
            self.last_evidence = None

            self.forwarded_packets += 1
            self.decision_stats["ALLOW"] += 1
            return "ALLOW"

        five_tuple, _ = parsed

        flow = self.flow_tracker.update(
            five_tuple,
            packet_size
        )

        domain = SNIExtractor.extract_http_host(packet)
        evidence_source = "http_host"

        if not domain:
            domain = TLSParser.extract_sni(packet)
            evidence_source = "tls_sni"

        if not domain:
            domain = DNSExtractor.extract_query(packet)
            evidence_source = "dns"

        result = ApplicationClassifier.classify_with_confidence(
            domain,
            evidence_source
        )

        application = result.application

        self.last_domain = domain
        self.last_application = application
        self.last_confidence = result.confidence
        self.last_evidence = result.evidence

        if application:
            flow.application = application

            self.application_stats[application] = (
                self.application_stats.get(application, 0) + 1
            )

        decision = self.rules.decide(application)

        flow.decision = decision

        self.decision_stats[decision] = (
            self.decision_stats.get(decision, 0) + 1
        )

        if decision == "BLOCK":
            self.blocked_packets += 1
        else:
            self.forwarded_packets += 1

        return decision

    def get_statistics(self):

        return {
            "total_packets": self.total_packets,
            "forwarded_packets": self.forwarded_packets,
            "blocked_packets": self.blocked_packets,
            "flows": self.flow_tracker.get_flow_count(),
            "total_bytes": self.total_bytes,
            "applications": dict(self.application_stats),
            "decisions": dict(self.decision_stats),
        }
