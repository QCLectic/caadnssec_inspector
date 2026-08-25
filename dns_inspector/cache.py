class DNSCache:
    """Cache DNS lookup results to avoid redundant queries."""

    def __init__(self):
        self.cache = {}
        self.hit_count = 0
        self.miss_count = 0

    def get(self, domain, record_type):
        """Get cached result if available."""
        key = (domain.lower(), record_type)
        if key in self.cache:
            self.hit_count += 1
            return self.cache[key]
        self.miss_count += 1
        return None

    def store(self, domain, record_type, result):
        """Store result in cache."""
        key = (domain.lower(), record_type)
        self.cache[key] = result

    def get_stats(self):
        """Return cache statistics."""
        total = self.hit_count + self.miss_count
        hit_rate = (self.hit_count / total) * 100 if total > 0 else 0
        return {
            'hits': self.hit_count,
            'misses': self.miss_count,
            'total': total,
            'hit_rate': f"{hit_rate:.1f}%"
        }

    def clear(self):
        """Clear the cache."""
        self.cache.clear()
        self.hit_count = 0
        self.miss_count = 0
