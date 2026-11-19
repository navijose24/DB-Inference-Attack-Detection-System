import hashlib
import re
from collections import defaultdict
from datetime import datetime, timedelta

try:
    import sqlglot
    from sqlglot import exp as sqlglot_exp
    HAS_SQLGLOT = True
except ImportError:
    HAS_SQLGLOT = False

SENSITIVE_COLUMNS = frozenset({'salary', 'ssn', 'designation', 'phone', 'address', 'dob'})

# Weights for combining individual attack scores
_ATTACK_WEIGHTS = {
    'differencing': 0.35,
    'small_set': 0.25,
    'repeated': 0.20,
    'attribute': 0.20,
}

# History window for session-based tracking
_HISTORY_WINDOW = timedelta(hours=1)


class QueryAnalyzer:
    """Analyzes SQL queries for inference attack patterns."""

    def __init__(self, config=None):
        self.config = config or {}
        self.small_set_threshold = self.config.get('SMALL_SET_THRESHOLD', 3)
        self.similarity_threshold = self.config.get('SIMILARITY_THRESHOLD', 0.85)
        # In-memory cache for session-based tracking
        self._query_history = defaultdict(list)  # user_id -> [(timestamp, query_hash, parsed_info)]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, query_text, user_id=None):
        """
        Returns dict with attack_types, risk_score, classification, details, parsed.
        """
        parsed = self._parse_query(query_text)

        attack_results = {
            'differencing': self._detect_differencing_attack(parsed, query_text, user_id),
            'small_set': self._detect_small_set_attack(parsed),
            'repeated': self._detect_repeated_query_attack(parsed, query_text, user_id),
            'attribute': self._detect_attribute_inference(parsed),
        }

        risk_score = self._compute_risk_score(attack_results)
        classification = self._classify_query(risk_score, self.config)

        attack_types = [k for k, v in attack_results.items() if v.get('score', 0) > 0.3]

        # Record for future session-based detection
        if user_id:
            self._record_query(user_id, query_text, parsed)

        return {
            'attack_types': attack_types,
            'risk_score': risk_score,
            'classification': classification,
            'details': attack_results,
            'parsed': parsed,
        }

    # ------------------------------------------------------------------
    # (a) SQL Parsing
    # ------------------------------------------------------------------

    def _parse_query(self, query_text):
        """Parse SQL via sqlglot, fall back to regex on failure."""
        info = {
            'tables': [],
            'columns': [],
            'sensitive_columns': [],
            'where_conditions': [],
            'group_by': [],
            'has_where': False,
            'has_group_by': False,
            'has_having': False,
            'has_aggregate': False,
            'aggregates': [],
            'order_by': [],
            'limit_value': None,
            'result_set_estimate': None,
        }

        if HAS_SQLGLOT:
            try:
                return self._parse_with_sqlglot(query_text, info)
            except Exception:
                pass  # fall through to regex

        return self._parse_with_regex(query_text, info)

    def _parse_with_sqlglot(self, query_text, info):
        tree = sqlglot.parse_one(query_text, error_level=sqlglot.ErrorLevel.WARN)

        # Tables
        for table in tree.find_all(sqlglot_exp.Table):
            name = table.name
            if name:
                info['tables'].append(name.lower())

        # Columns from SELECT
        for col in tree.find_all(sqlglot_exp.Column):
            name = col.name
            if name:
                col_lower = name.lower()
                info['columns'].append(col_lower)
                if col_lower in SENSITIVE_COLUMNS:
                    info['sensitive_columns'].append(col_lower)

        # Aggregates
        agg_types = (
            sqlglot_exp.Count, sqlglot_exp.Sum, sqlglot_exp.Avg,
            sqlglot_exp.Min, sqlglot_exp.Max,
        )
        for agg in tree.find_all(*agg_types):
            info['aggregates'].append(type(agg).__name__.upper())
        info['has_aggregate'] = bool(info['aggregates'])

        # WHERE
        where = tree.find(sqlglot_exp.Where)
        info['has_where'] = where is not None
        if where:
            info['where_conditions'] = self._extract_conditions(where)

        # GROUP BY
        group = tree.find(sqlglot_exp.Group)
        info['has_group_by'] = group is not None
        if group:
            for col in group.find_all(sqlglot_exp.Column):
                info['group_by'].append(col.name.lower() if col.name else '')

        # HAVING
        info['has_having'] = tree.find(sqlglot_exp.Having) is not None

        # ORDER BY
        order = tree.find(sqlglot_exp.Order)
        if order:
            for col in order.find_all(sqlglot_exp.Column):
                info['order_by'].append(col.name.lower() if col.name else '')

        # LIMIT
        limit = tree.find(sqlglot_exp.Limit)
        if limit:
            lit = limit.find(sqlglot_exp.Literal)
            if lit:
                try:
                    info['limit_value'] = int(lit.this)
                except (ValueError, TypeError):
                    pass

        # Rough result-set estimate
        info['result_set_estimate'] = self._estimate_result_set(info)

        return info

    def _extract_conditions(self, where_node):
        """Walk WHERE tree and pull out (column, operator, value) triples."""
        conditions = []
        for eq in where_node.find_all(sqlglot_exp.EQ):
            col, val = self._col_val_from_binary(eq)
            if col:
                conditions.append({'column': col, 'operator': '=', 'value': val})
        for neq in where_node.find_all(sqlglot_exp.NEQ):
            col, val = self._col_val_from_binary(neq)
            if col:
                conditions.append({'column': col, 'operator': '!=', 'value': val})
        for gt in where_node.find_all(sqlglot_exp.GT):
            col, val = self._col_val_from_binary(gt)
            if col:
                conditions.append({'column': col, 'operator': '>', 'value': val})
        for lt in where_node.find_all(sqlglot_exp.LT):
            col, val = self._col_val_from_binary(lt)
            if col:
                conditions.append({'column': col, 'operator': '<', 'value': val})
        for gte in where_node.find_all(sqlglot_exp.GTE):
            col, val = self._col_val_from_binary(gte)
            if col:
                conditions.append({'column': col, 'operator': '>=', 'value': val})
        for lte in where_node.find_all(sqlglot_exp.LTE):
            col, val = self._col_val_from_binary(lte)
            if col:
                conditions.append({'column': col, 'operator': '<=', 'value': val})
        for like in where_node.find_all(sqlglot_exp.Like):
            col, val = self._col_val_from_binary(like)
            if col:
                conditions.append({'column': col, 'operator': 'LIKE', 'value': val})
        for in_ in where_node.find_all(sqlglot_exp.In):
            col_node = in_.find(sqlglot_exp.Column)
            if col_node:
                conditions.append({'column': col_node.name.lower(), 'operator': 'IN', 'value': str(in_)})
        return conditions

    @staticmethod
    def _col_val_from_binary(node):
        col_node = node.find(sqlglot_exp.Column)
        lit_node = node.find(sqlglot_exp.Literal)
        if col_node:
            col = col_node.name.lower()
            val = lit_node.this if lit_node else str(node.right)
            return col, val
        return None, None

    def _parse_with_regex(self, query_text, info):
        """Best-effort regex fallback when sqlglot is unavailable or fails."""
        upper = query_text.upper()

        # Tables (FROM / JOIN)
        for m in re.finditer(r'(?:FROM|JOIN)\s+(\w+)', query_text, re.IGNORECASE):
            info['tables'].append(m.group(1).lower())

        # Columns in SELECT ... FROM
        sel_match = re.search(r'SELECT\s+(.*?)\s+FROM', query_text, re.IGNORECASE | re.DOTALL)
        if sel_match:
            cols_raw = sel_match.group(1)
            for part in cols_raw.split(','):
                part = part.strip()
                # Skip aggregate wrappers to find inner column
                inner = re.search(r'\((\w+)\)', part)
                if inner:
                    info['columns'].append(inner.group(1).lower())
                else:
                    token = part.split()[-1].strip('`"[] ')
                    if token != '*':
                        info['columns'].append(token.lower())

        info['sensitive_columns'] = [c for c in info['columns'] if c in SENSITIVE_COLUMNS]

        # Aggregates
        for agg in re.findall(r'(COUNT|SUM|AVG|MIN|MAX)\s*\(', upper):
            info['aggregates'].append(agg)
        info['has_aggregate'] = bool(info['aggregates'])

        # WHERE conditions
        where_match = re.search(r'WHERE\s+(.*?)(?:GROUP|ORDER|LIMIT|HAVING|$)', query_text, re.IGNORECASE | re.DOTALL)
        info['has_where'] = bool(where_match)
        if where_match:
            cond_text = where_match.group(1)
            for m in re.finditer(r"(\w+)\s*(=|!=|<>|>=|<=|>|<|LIKE)\s*'?([^']*?)'?(?:\s+AND|\s+OR|\s*$)", cond_text, re.IGNORECASE):
                info['where_conditions'].append({
                    'column': m.group(1).lower(),
                    'operator': m.group(2).upper(),
                    'value': m.group(3),
                })

        # GROUP BY
        gb = re.search(r'GROUP\s+BY\s+(.*?)(?:HAVING|ORDER|LIMIT|$)', query_text, re.IGNORECASE | re.DOTALL)
        info['has_group_by'] = bool(gb)
        if gb:
            info['group_by'] = [c.strip().lower() for c in gb.group(1).split(',')]

        info['has_having'] = 'HAVING' in upper

        # ORDER BY
        ob = re.search(r'ORDER\s+BY\s+(.*?)(?:LIMIT|$)', query_text, re.IGNORECASE | re.DOTALL)
        if ob:
            info['order_by'] = [c.strip().split()[0].lower() for c in ob.group(1).split(',')]

        # LIMIT
        lm = re.search(r'LIMIT\s+(\d+)', query_text, re.IGNORECASE)
        if lm:
            info['limit_value'] = int(lm.group(1))

        info['result_set_estimate'] = self._estimate_result_set(info)
        return info

    @staticmethod
    def _estimate_result_set(info):
        """Rough heuristic estimate of how many rows a query might return."""
        conditions = info.get('where_conditions', [])
        if not conditions:
            return None  # unknown / full table

        eq_count = sum(1 for c in conditions if c.get('operator') == '=')
        and_count = len(conditions)

        # Many equality conditions on different columns → very narrow
        if eq_count >= 3:
            return 1
        if eq_count == 2 and and_count >= 2:
            return 3
        if eq_count == 1:
            return 10
        return None

    # ------------------------------------------------------------------
    # (b) Differencing attack
    # ------------------------------------------------------------------

    def _detect_differencing_attack(self, parsed_info, query_text, user_id):
        """
        Two queries differing by exactly one WHERE condition, with aggregates,
        can reveal an individual's value via subtraction.
        """
        result = {'score': 0.0, 'description': '', 'matched_query': None}

        if not parsed_info.get('has_aggregate'):
            return result

        if not user_id or user_id not in self._query_history:
            # First query in session — can't compare yet, but flag if it
            # has the right shape (aggregate + WHERE on sensitive col)
            if parsed_info.get('has_where') and parsed_info.get('sensitive_columns'):
                result['score'] = 0.15
                result['description'] = 'Aggregate on sensitive column with filter — potential first half of differencing attack.'
            return result

        now = datetime.utcnow()
        history = self._query_history[user_id]

        best_score = 0.0
        for ts, _, prev_parsed in reversed(history):
            if now - ts > _HISTORY_WINDOW:
                break
            sim = self._structural_similarity(parsed_info, prev_parsed)
            # Differencing queries typically have ~0.70 - 0.85 similarity due to altered WHERE clauses
            if sim < 0.70:
                continue

            # Same aggregates?
            if set(parsed_info.get('aggregates', [])) != set(prev_parsed.get('aggregates', [])):
                continue

            # Differ by exactly one WHERE condition?
            cur_conds = {(c['column'], c['value']) for c in parsed_info.get('where_conditions', [])}
            prev_conds = {(c['column'], c['value']) for c in prev_parsed.get('where_conditions', [])}
            added = cur_conds - prev_conds
            removed = prev_conds - cur_conds

            diff_count = len(added) + len(removed)
            if diff_count == 0:
                continue  # identical

            score = 0.0
            if diff_count == 1:
                score = 0.9
            elif diff_count == 2:
                score = 0.6
            else:
                score = 0.3

            # Boost if the extra condition is on a unique-ish column
            unique_cols = {'name', 'emp_id', 'employee_id', 'id', 'ssn', 'email'}
            narrowing_cols = {c for c, _ in added}
            if narrowing_cols & unique_cols:
                score = min(1.0, score + 0.1)

            if score > best_score:
                best_score = score
                result['matched_query'] = prev_parsed

        result['score'] = best_score
        if best_score >= 0.5:
            result['description'] = 'Queries differ by one WHERE condition with same aggregates — classic differencing attack pattern.'
        elif best_score > 0:
            result['description'] = 'Partial differencing pattern detected.'

        return result

    # ------------------------------------------------------------------
    # (c) Small-set attack
    # ------------------------------------------------------------------

    def _detect_small_set_attack(self, parsed_info):
        """
        Aggregate or direct selection on sensitive column with WHERE that returns very few rows.
        """
        result = {'score': 0.0, 'description': ''}

        has_agg = parsed_info.get('has_aggregate', False)
        sensitive_cols = parsed_info.get('sensitive_columns', [])
        estimate = parsed_info.get('result_set_estimate')
        conditions = parsed_info.get('where_conditions', [])
        eq_count = sum(1 for c in conditions if c.get('operator') == '=')

        # Unique-ish column equality
        unique_cols = {'name', 'emp_id', 'employee_id', 'id', 'ssn', 'ssn_last4', 'email'}
        unique_hit = any(c['column'] in unique_cols for c in conditions if c.get('operator') == '=')

        score = 0.0

        if unique_hit:
            score = 0.90 if (has_agg or sensitive_cols) else 0.70
        elif estimate is not None and estimate <= self.small_set_threshold:
            score = 0.80 if (has_agg or sensitive_cols) else 0.60
        elif eq_count >= 3:
            score = 0.70 if (has_agg or sensitive_cols) else 0.50
        elif eq_count >= 2 and sensitive_cols:
            score = 0.55
        elif eq_count >= 1 and sensitive_cols and has_agg:
            score = 0.40

        # Boost if sensitive columns are targeted
        if sensitive_cols and score > 0:
            score = min(1.0, score + 0.1)

        result['score'] = score
        if score >= 0.5:
            result['description'] = (
                f'Query with highly restrictive WHERE (est. {estimate or 1} rows) '
                f'targets sensitive column(s): {sensitive_cols or "records"}.'
            )
        elif score > 0:
            result['description'] = 'Moderately narrow query filtering specific records.'

        return result

    # ------------------------------------------------------------------
    # (d) Repeated / enumeration attack
    # ------------------------------------------------------------------

    def _detect_repeated_query_attack(self, parsed_info, query_text, user_id):
        """
        Many structurally similar queries with varying WHERE values →
        systematic enumeration.
        """
        result = {'score': 0.0, 'description': '', 'similar_count': 0}

        if not user_id or user_id not in self._query_history:
            return result

        now = datetime.utcnow()
        history = self._query_history[user_id]
        similar_count = 0

        for ts, _, prev_parsed in reversed(history):
            if now - ts > _HISTORY_WINDOW:
                break
            sim = self._structural_similarity(parsed_info, prev_parsed)
            if sim >= self.similarity_threshold:
                # Check that WHERE values differ (same structure, different data)
                cur_vals = {c.get('value') for c in parsed_info.get('where_conditions', [])}
                prev_vals = {c.get('value') for c in prev_parsed.get('where_conditions', [])}
                if cur_vals != prev_vals:
                    similar_count += 1

        result['similar_count'] = similar_count

        if similar_count >= 8:
            result['score'] = 0.95
        elif similar_count >= 5:
            result['score'] = 0.75
        elif similar_count >= 3:
            result['score'] = 0.55
        elif similar_count >= 2:
            result['score'] = 0.35
        else:
            result['score'] = 0.0

        if result['score'] >= 0.5:
            result['description'] = (
                f'{similar_count} structurally similar queries with varying WHERE values '
                f'in the last hour — systematic enumeration pattern.'
            )
        elif result['score'] > 0:
            result['description'] = f'{similar_count} similar queries detected — early enumeration signal.'

        return result

    # ------------------------------------------------------------------
    # (e) Attribute inference
    # ------------------------------------------------------------------

    def _detect_attribute_inference(self, parsed_info):
        """
        Combining non-sensitive columns in WHERE to narrow down to an
        individual, then selecting sensitive columns.
        """
        result = {'score': 0.0, 'description': ''}

        sensitive_selected = parsed_info.get('sensitive_columns', [])
        if not sensitive_selected:
            return result

        conditions = parsed_info.get('where_conditions', [])
        if not conditions:
            return result

        # Count non-sensitive filter columns
        non_sensitive_filters = [
            c for c in conditions
            if c['column'] not in SENSITIVE_COLUMNS and c.get('operator') == '='
        ]
        narrowing_cols = {'gender', 'dept', 'department', 'age', 'city', 'state',
                          'position', 'title', 'location', 'office', 'floor', 'team'}
        narrowing_hit = sum(1 for c in non_sensitive_filters if c['column'] in narrowing_cols)

        score = 0.0
        if narrowing_hit >= 3:
            score = 0.85
        elif narrowing_hit >= 2:
            score = 0.6
        elif len(non_sensitive_filters) >= 3:
            score = 0.55
        elif narrowing_hit >= 1 and len(sensitive_selected) >= 1:
            score = 0.35
        elif len(non_sensitive_filters) >= 1 and len(sensitive_selected) >= 2:
            score = 0.3

        # Boost for no GROUP BY (direct row access intent)
        if not parsed_info.get('has_group_by') and score > 0:
            score = min(1.0, score + 0.05)

        result['score'] = score
        if score >= 0.5:
            result['description'] = (
                f'Query narrows via {narrowing_hit} quasi-identifier column(s) and selects '
                f'sensitive column(s) {sensitive_selected} — attribute inference pattern.'
            )
        elif score > 0:
            result['description'] = 'Mild attribute inference signal.'

        return result

    # ------------------------------------------------------------------
    # (f) Risk score aggregation
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_risk_score(attack_results):
        """
        Risk is driven by the most severe attack signature, with compound
        weighting for multi-vector attacks.
        """
        scores = [attack_results[k].get('score', 0) for k in _ATTACK_WEIGHTS]
        max_score = max(scores) if scores else 0.0
        weighted_sum = sum(
            _ATTACK_WEIGHTS[k] * attack_results[k].get('score', 0)
            for k in _ATTACK_WEIGHTS
        )
        total = max(max_score, weighted_sum * 1.5)
        return min(1.0, max(0.0, total))

    # ------------------------------------------------------------------
    # (g) Classification
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_query(risk_score, config):
        block_thresh = config.get('RISK_THRESHOLD_BLOCK', 0.8) if config else 0.8
        flag_thresh = config.get('RISK_THRESHOLD_FLAG', 0.5) if config else 0.5
        if risk_score >= block_thresh:
            return 'BLOCKED'
        if risk_score >= flag_thresh:
            return 'FLAGGED'
        if risk_score >= 0.3:
            return 'SUSPICIOUS'
        return 'SAFE'

    # ------------------------------------------------------------------
    # (h) Record query in history
    # ------------------------------------------------------------------

    def _record_query(self, user_id, query_text, parsed_info):
        now = datetime.utcnow()
        qhash = self._compute_query_hash(query_text)
        self._query_history[user_id].append((now, qhash, parsed_info))
        # Prune entries older than the window
        cutoff = now - _HISTORY_WINDOW
        self._query_history[user_id] = [
            (ts, h, p) for ts, h, p in self._query_history[user_id] if ts >= cutoff
        ]

    # ------------------------------------------------------------------
    # (i) Query hash
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_query_hash(query_text):
        normalized = ' '.join(query_text.lower().split())
        return hashlib.sha256(normalized.encode()).hexdigest()

    # ------------------------------------------------------------------
    # (j) Structural similarity
    # ------------------------------------------------------------------

    @staticmethod
    def _structural_similarity(parsed1, parsed2):
        """Compare two parsed query infos; return 0-1 similarity score."""
        score = 0.0
        total_weight = 0.0

        # Same table(s)?  (weight 3)
        w = 3.0
        total_weight += w
        t1 = set(parsed1.get('tables', []))
        t2 = set(parsed2.get('tables', []))
        if t1 and t2:
            score += w * len(t1 & t2) / max(len(t1 | t2), 1)

        # Same aggregates? (weight 2)
        w = 2.0
        total_weight += w
        a1 = set(parsed1.get('aggregates', []))
        a2 = set(parsed2.get('aggregates', []))
        if a1 == a2 and a1:
            score += w
        elif a1 and a2:
            score += w * len(a1 & a2) / max(len(a1 | a2), 1)

        # Same selected columns? (weight 2)
        w = 2.0
        total_weight += w
        c1 = set(parsed1.get('columns', []))
        c2 = set(parsed2.get('columns', []))
        if c1 and c2:
            score += w * len(c1 & c2) / max(len(c1 | c2), 1)

        # Similar WHERE structure? (weight 2) — same filter columns
        w = 2.0
        total_weight += w
        wc1 = {c['column'] for c in parsed1.get('where_conditions', [])}
        wc2 = {c['column'] for c in parsed2.get('where_conditions', [])}
        if wc1 and wc2:
            score += w * len(wc1 & wc2) / max(len(wc1 | wc2), 1)

        # Same GROUP BY? (weight 1)
        w = 1.0
        total_weight += w
        g1 = set(parsed1.get('group_by', []))
        g2 = set(parsed2.get('group_by', []))
        if g1 == g2:
            score += w

        return score / total_weight if total_weight else 0.0
