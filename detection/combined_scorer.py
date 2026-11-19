class CombinedScorer:
    def __init__(self, rule_weight=0.6, ml_weight=0.4):
        self.rule_weight = rule_weight
        self.ml_weight = ml_weight

    def compute_combined_score(self, rule_score, ml_score):
        """Weighted combination, clamped to [0, 1]."""
        combined = self.rule_weight * rule_score + self.ml_weight * ml_score
        # Decisive threat priority: if rule or ML is very high, avoid over-dilution
        if rule_score >= 0.8:
            combined = max(combined, rule_score * 0.95)
        elif ml_score >= 0.85:
            combined = max(combined, ml_score * 0.90)
        elif rule_score > 0.5 and ml_score > 0.5:
            combined = min(1.0, combined * 1.15)
        return min(1.0, max(0.0, combined))

    def classify(self, combined_score, block_threshold=0.8, flag_threshold=0.5):
        if combined_score >= block_threshold:
            return "BLOCKED"
        elif combined_score >= flag_threshold:
            return "FLAGGED"
        elif combined_score >= 0.3:
            return "SUSPICIOUS"
        return "SAFE"
