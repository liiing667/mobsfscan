"""Tests for finding deduplication across scanners."""
from mobsfscan.mobsfscan import MobSFScan


def _scan_with_results(results):
    scanner = MobSFScan.__new__(MobSFScan)
    scanner.result = {'results': results, 'errors': []}
    scanner.deduplicate_files()
    return scanner.result


def test_dedup_tolerates_list_valued_fields():
    """List values (e.g. match_lines) must not raise TypeError."""
    finding = {
        'file_path': 'res/values/strings.xml',
        'match_lines': [1, 1],
        'match_string': 'AIza-secret',
        'bad_field': ['a', 'b'],
    }
    result = _scan_with_results({
        'google_api_key': {'files': [finding, dict(finding)]},
    })
    files = result['results']['google_api_key']['files']
    assert len(files) == 1
    assert files[0]['file_path'] == 'res/values/strings.xml'
    assert files[0]['bad_field'] == ['a', 'b']


def test_dedup_merges_source_and_xml_same_key():
    """Same rule hitting source and XML merges into one finding."""
    source = {
        'file_path': 'app/Secrets.java',
        'match_lines': (10, 10),
        'match_string': 'AIza-source',
        'match_position': (4, 40),
    }
    xml = dict(source)
    result = _scan_with_results({
        'google_api_key': {'files': [source, xml]},
    })
    files = result['results']['google_api_key']['files']
    assert len(files) == 1
    assert files[0]['match_position'] == (4, 40)


def test_dedup_keeps_distinct_findings_and_sorts_them():
    """Different files stay distinct; output order is deterministic."""
    first = {
        'file_path': 'b/Manifest.xml',
        'match_lines': (5, 5),
        'match_string': 'z',
    }
    second = {
        'file_path': 'a/Manifest.xml',
        'match_lines': (1, 1),
        'match_string': 'a',
    }
    result = _scan_with_results({
        'rule': {'files': [first, second]},
    })
    files = result['results']['rule']['files']
    assert [item['file_path'] for item in files] == [
        'a/Manifest.xml', 'b/Manifest.xml']


def test_dedup_normalizes_line_range_for_key():
    """Tuple vs list representations of the same range merge."""
    forward = {
        'file_path': 'AndroidManifest.xml',
        'match_lines': [3, 7],
        'match_string': 'debuggable',
    }
    as_tuple = {
        'file_path': 'AndroidManifest.xml',
        'match_lines': (3, 7),
        'match_string': 'debuggable',
    }
    result = _scan_with_results({
        'rule': {'files': [forward, as_tuple]},
    })
    files = result['results']['rule']['files']
    assert len(files) == 1


def test_dedup_preserves_conflicting_extra_fields():
    """Conflicting non-key fields are retained instead of overwritten."""
    first = {
        'file_path': 'a.xml',
        'match_lines': (1, 1),
        'match_string': 'x',
        'match_position': (1, 2),
    }
    second = {
        'file_path': 'a.xml',
        'match_lines': [1, 1],
        'match_string': 'x',
        'match_position': (9, 9),
    }
    result = _scan_with_results({
        'rule': {'files': [first, second]},
    })
    files = result['results']['rule']['files']
    assert len(files) == 1
    assert files[0]['match_position'] == (1, 2)
    assert files[0]['dedupe_extra_values'] == {
        'match_position': [(1, 2), (9, 9)]}


def test_dedup_handles_missing_and_malformed_fields():
    """Findings lacking key fields or with weird types never crash."""
    result = _scan_with_results({
        'rule': {
            'files': [
                {'file_path': 'a.xml'},
                {'file_path': 'a.xml'},
                {
                    'file_path': 'b.xml',
                    'match_lines': {'unexpected': 'dict'},
                    'match_string': {'also': 'dict'},
                },
            ],
        },
    })
    files = result['results']['rule']['files']
    assert len(files) == 2
    assert files[0]['file_path'] == 'a.xml'
    assert files[1]['file_path'] == 'b.xml'
