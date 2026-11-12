# -*- coding: utf_8 -*-
"""The MobSF cli: mobsfscan."""
from pathlib import Path
from linecache import getline

from libsast import (
    Scanner,
    standards,
)

from mobsfscan.logger import init_logger
from mobsfscan import settings
from mobsfscan import manifest
from mobsfscan import ios_plist
from mobsfscan.utils import (
    get_best_practices,
    get_config,
)


logger = init_logger(__name__)

# Finding fields used to build the stable deduplication key.
_DEDUP_KEY_FIELDS = ('file_path', 'match_lines', 'match_string')
# Sort order used when a field holds an unexpected (non-scalar) type.
_TYPE_ORDER = {
    int: 0,
    float: 1,
    str: 2,
    tuple: 3,
    list: 4,
    type(None): 5,
}


def _stable_scalar(value):
    """Return a hashable, orderable representation of a finding field."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return tuple(_stable_scalar(item) for item in value)
    # Dicts/sets/other unhashable values: keep the data via its repr
    # instead of dropping the finding.
    return repr(value)


def _normalized_lines(match_lines):
    """Normalize a match_lines value to an (start, end) int pair."""
    if isinstance(match_lines, (list, tuple)) and len(match_lines) == 2:
        try:
            start, end = int(match_lines[0]), int(match_lines[1])
        except (TypeError, ValueError):
            pass
        else:
            if end < start:
                end = start
            return start, end
    # Malformed span: keep the raw value but make it key-safe.
    return _stable_scalar(match_lines)


def _finding_key(finding):
    """Stable key: file path, normalized line range and matched content."""
    return (
        _stable_scalar(finding.get('file_path')),
        _normalized_lines(finding.get('match_lines')),
        _stable_scalar(finding.get('match_string')),
    )


def _sort_key(key):
    """Deterministic, type-safe ordering for finding keys."""
    return tuple(
        (_TYPE_ORDER.get(type(part), 6), part) for part in key)


class MobSFScan:
    def __init__(
            self,
            paths,
            json,
            scan_type='auto',
            config=False,
            mp='default') -> None:
        self.scan_type = scan_type
        self.conf = get_config(paths, config)
        self.options = {
            'match_rules': None,
            'sgrep_rules': None,
            'sgrep_extensions': None,
            'match_extensions': None,
            'ignore_filenames': self.conf['ignore_filenames'],
            'ignore_extensions': self.conf['ignore_extensions'],
            'ignore_paths': self.conf['ignore_paths'],
            'ignore_rules': self.conf['ignore_rules'],
            'severity_filter': self.conf['severity_filter'],
            'severity_overrides': self.conf['severity_overrides'],
            'show_progress': not json,
            'multiprocessing': mp,
        }
        self.paths = paths
        self.result = {
            'results': {},
            'errors': [],
        }
        self.xmls = []
        self.plists = []
        # Extensions whose BP presence hits must be stripped (may be a
        # superset of languages actually present — see missing_controls).
        self.best_practices_invert = set()
        # Extensions for which absent controls are reported as missing.
        self.best_practices_missing = set()
        self.standards = standards.get_standards()
        self.get_extensions()
        self.get_xmls()
        self.get_plists()

    def _configure_android(self, present):
        """Semgrep Android rules; invert both Java and Kotlin BP dialects."""
        self.options['match_rules'] = None
        self.options['match_extensions'] = None
        self.options['sgrep_rules'] = settings.SGREP_RULES_DIR.as_posix()
        self.options['sgrep_extensions'] = {'.java', '.kt'}
        # Presence rules for both dialects are loaded; always strip both.
        self.best_practices_invert = {'.java', '.kt'}
        # Only report missing controls for languages actually in the scan.
        self.best_practices_missing = set(present)

    def _configure_ios(self, present):
        """Swift Semgrep + ObjC regex; invert both iOS BP dialects."""
        self.options['match_rules'] = (
            settings.IOS_RULES_DIR / 'objectivec').as_posix()
        self.options['match_extensions'] = {'.m'}
        self.options['sgrep_rules'] = settings.SGREP_RULES_DIR.as_posix()
        self.options['sgrep_extensions'] = {'.swift'}
        self.best_practices_invert = {'.swift', '.m'}
        self.best_practices_missing = set(present)

    def get_extensions(self) -> set:
        """Discover source suffixes and configure scanners."""
        scan_suffix = {'.java', '.kt', '.swift', '.m'}
        found = set()
        for path in self.paths:
            pobj = Path(path)
            if pobj.is_dir():
                for pfile in pobj.rglob('*'):
                    if pfile.suffix in scan_suffix:
                        found.add(pfile.suffix)
            elif pobj.suffix in scan_suffix:
                found.add(pobj.suffix)

        android = found & {'.java', '.kt'}
        ios = found & {'.swift', '.m'}
        # Configure only when matching sources exist (plist/xml-only trees
        # should not invent missing-control findings for .kt/.swift).
        if self.scan_type == 'android':
            if android:
                self._configure_android(android)
        elif self.scan_type == 'ios':
            if ios:
                self._configure_ios(ios)
        elif android:
            self._configure_android(android)
        elif ios:
            self._configure_ios(ios)

    def get_xmls(self) -> set:
        """Get XML files for scanning."""
        for path in self.paths:
            pobj = Path(path)
            if pobj.is_dir():
                for pfile in pobj.rglob('*'):
                    if pfile.suffix == '.xml':
                        self.xmls.append(pfile)
            else:
                if pobj.suffix == '.xml':
                    self.xmls.append(pobj)

    def get_plists(self) -> set:
        """Get Info.plist files for scanning."""
        for path in self.paths:
            pobj = Path(path)
            if pobj.is_dir():
                for pfile in pobj.rglob('Info.plist'):
                    self.plists.append(pfile)
            elif pobj.name == 'Info.plist':
                self.plists.append(pobj)

    def scan(self) -> dict:
        """Start Scan."""
        scanner = Scanner(self.options, self.paths)
        result = scanner.scan()
        try:
            # Keep beta for a while
            if self.xmls and self.scan_type in ('auto', 'android'):
                result['xml_checks'] = manifest.scan_manifest(
                    self.xmls,
                    scanner.validate_file)
        except Exception:
            logger.warning(
                'Android XML checks failed. '
                'Please report to mobsfscan project')
        try:
            if self.plists and self.scan_type in ('auto', 'ios'):
                result['plist_checks'] = ios_plist.scan_plists(
                    self.plists,
                    scanner.validate_file,
                )
        except Exception:
            logger.warning(
                'iOS Info.plist checks failed. '
                'Please report to mobsfscan project')

        if result:
            self.format_output(result)
        return self.result

    def format_output(self, results) -> dict:
        """Format to mobsfscan friendly output."""
        self.format_semgrep(results.get('semantic_grep'))
        self.format_pattern(results.get('pattern_matcher'))
        self.format_pattern(results.get('xml_checks'))
        self.format_pattern(results.get('plist_checks'))
        self.missing_controls()
        self.post_ignore_rules()
        self.post_override_severities()
        self.post_ignore_rules_by_severity()
        self.post_ignore_files()
        self.deduplicate_files()

    def deduplicate_files(self):
        """Deduplicate findings across source and XML/manifest scanners.

        Findings are merged on a stable key made of the file path, the
        normalized line range and the matched content. Raw findings may
        carry list-valued or otherwise unhashable fields, so the key is
        built defensively rather than hashing the whole dict; malformed
        fields are preserved on the merged finding instead of crashing or
        dropping data. Output order is deterministic.
        """
        for _, details in self.result['results'].items():
            files = details.get('files')
            # Some results don't have any files.
            if not files:
                continue
            merged = {}
            order = []
            for finding in files:
                key = _finding_key(finding)
                current = merged.get(key)
                if current is None:
                    merged[key] = dict(finding)
                    order.append(key)
                    continue
                # Same logical finding from another scanner: merge the
                # sources and conservatively keep any extra/bad fields.
                for field, value in finding.items():
                    if field in _DEDUP_KEY_FIELDS:
                        continue
                    if field not in current:
                        current[field] = value
                    elif current[field] != value:
                        extras = current.setdefault(
                            'dedupe_extra_values', {})
                        extras.setdefault(field, [current[field]])
                        if value not in extras[field]:
                            extras[field].append(value)
            details['files'] = [
                merged[key] for key in sorted(order, key=_sort_key)]

    def format_semgrep(self, sgrep_output):
        """Format semgrep output."""
        if not sgrep_output:
            return
        self.result['errors'] = sgrep_output['errors']
        for rule_id in sgrep_output['matches']:
            for finding in sgrep_output['matches'][rule_id]['files']:
                finding.pop('metavars', None)
        self.result['results'] = sgrep_output['matches']

    def format_pattern(self, matcher_out):
        """Format Pattern Matcher output.

        Merge files when Semgrep already reported the same rule id, so an
        XML hit does not replace a source hit.
        """
        if not matcher_out:
            return
        for rule_id, details in matcher_out.items():
            existing = self.result['results'].get(rule_id)
            if not existing:
                self.result['results'][rule_id] = details
                continue
            extra = details.get('files') or []
            if not extra:
                continue
            files = existing.get('files')
            if files is None:
                existing['files'] = list(extra)
            else:
                files.extend(extra)

    def format_xml(self, res_out):
        """Format XML check output."""
        if not res_out:
            return
        self.result['results'].update(res_out)

    def missing_controls(self):
        """Check for missing controls.

        Semgrep loads best-practice *presence* rules for every dialect under
        SGREP_RULES_DIR. Invert (delete) the union of related dialects so
        presence hits never leak, but only *report* missing controls for
        languages actually present in the scan paths.
        """
        if not self.best_practices_invert and not self.best_practices_missing:
            return
        invert_ids, _ = get_best_practices(self.best_practices_invert)
        missing_ids, rules = get_best_practices(self.best_practices_missing)
        result_keys = set(self.result['results'].keys())
        deleted = set()
        for rule_id in invert_ids:
            if rule_id in result_keys:
                # Control Present
                deleted.add(rule_id)
                del self.result['results'][rule_id]
        # Add Missing (only for languages present in the scan)
        for rule_id in missing_ids.difference(result_keys):
            if rule_id in deleted:
                continue
            details = rules.get(rule_id)
            if not details:
                continue
            self.result['results'][rule_id] = {}
            res = self.result['results'][rule_id]
            res['metadata'] = details['metadata']
            res['metadata']['description'] = details['message']
            res['metadata']['severity'] = details['severity']
            self.expand_mappings(res)

    def expand_mappings(self, meta):
        """Expand libsast standard mappings for missing controls."""
        meta_keys = meta['metadata'].keys()
        for mkey in meta_keys:
            if mkey not in self.standards.keys():
                continue
            to_expand = meta['metadata'][mkey]
            expanded = self.standards[mkey].get(to_expand)
            if expanded:
                meta['metadata'][mkey] = expanded

    def post_ignore_rules(self):
        """Ignore findings by rules."""
        for rule_id in self.options['ignore_rules']:
            if rule_id in self.result['results']:
                del self.result['results'][rule_id]

    def post_override_severities(self):
        """Override finding severities from .mobsf severity-overrides."""
        overrides = self.options.get('severity_overrides') or {}
        if not overrides:
            return
        for rule_id, severity in overrides.items():
            details = self.result['results'].get(rule_id)
            if not details:
                continue
            meta = details.get('metadata')
            if not isinstance(meta, dict):
                continue
            meta['severity'] = severity

    def post_ignore_rules_by_severity(self):
        """Filter findings by rule severity."""
        del_keys = set()
        for rule_id, details in self.result['results'].items():
            issue_severity = details.get('metadata').get('severity')
            if issue_severity not in self.options['severity_filter']:
                del_keys.add(rule_id)
        for rid in del_keys:
            if rid in self.result['results']:
                del self.result['results'][rid]

    def suppress_pm_comments(self, obj, rule_id):
        """Return True if this match has a mobsf-ignore for rule_id."""
        file_path = obj.get('file_path')
        lines = obj.get('match_lines') or (0, 0)
        start, end = int(lines[0]), int(lines[1])
        if start <= 0:
            return False
        if end < start:
            end = start
        # Check every line in the reported span (covers libsast
        # off-by-one when a match starts at column 0).
        for lineno in range(start, end + 1):
            match_line = getline(file_path, lineno)
            if self._line_ignores_rule(match_line, rule_id):
                return True
        return False

    @staticmethod
    def _line_ignores_rule(match_line, rule_id):
        """Parse // mobsf-ignore: id1, id2 on a source line."""
        if not match_line or 'mobsf-ignore:' not in match_line:
            return False
        marker = match_line.split('mobsf-ignore:', 1)[1]
        # Stop at end of line comment content; split rule ids
        ids = []
        for part in marker.replace(',', ' ').split():
            token = part.strip().strip(',')
            if token:
                ids.append(token)
        return rule_id in ids

    def post_ignore_files(self):
        """Drop individual matches suppressed by mobsf-ignore comments."""
        del_keys = set()
        for rule_id, details in self.result['results'].items():
            files = details.get('files')
            if not files:
                continue
            kept = [
                match for match in files
                if not self.suppress_pm_comments(match, rule_id)
            ]
            details['files'] = kept
            if not kept:
                del_keys.add(rule_id)
        for rid in del_keys:
            self.result['results'].pop(rid, None)
