"""Export one account's evidence from a cross_mailbox SQLite index, offline."""
import argparse
import csv
import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

VERSION = '0.5.0-beta.2'
URL = 'https://github.com/mariovilnius/artefact-finder'
# Keep every disjunction inside parentheses following the mandatory account scope.
EXPORTS = {
    'mail-actions.csv': "kind IN ('mail_copy','mail_expunge','mail_delete_flag')",
    'positive-retr-or-deletion.csv': 'retr_commands > 0 OR del_counter > 0',
}


def viewing_cell(value):
    """CSV is a viewing export; raw evidence stays unchanged in the index."""
    if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@')):
        return "'" + value
    return value


def run(database, output, account):
    if not account or not account.strip():
        raise ValueError('An explicit nonempty account is required')
    database = Path(database).resolve()
    output = Path(output)
    # Read-only URI prevents creation/mutation of the input evidence index.
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute('SELECT account,kind,retr_commands,del_counter FROM events LIMIT 0')
        output.mkdir(parents=True, exist_ok=False)
        counts = {}
        for name, predicate in EXPORTS.items():
            cursor = db.execute(
                'SELECT * FROM events WHERE account = ? AND (' + predicate +
                ') ORDER BY second,file,line', (account,))
            with (output / name).open('w', encoding='utf-8-sig', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([column[0] for column in cursor.description])
                count = 0
                for row in cursor:
                    if row['account'] != account:
                        raise RuntimeError('Cross-account export rejected')
                    writer.writerow([viewing_cell(value) for value in row])
                    count += 1
            counts[name] = count
    manifest = dict(
        engine=dict(name='Artefact Finder', url=URL, version=VERSION),
        module='mailbox_csv', account=account,
        generated_at_utc=datetime.now(timezone.utc).isoformat(timespec='seconds'),
        module_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        counts=counts,
        files={name: hashlib.sha256((output / name).read_bytes()).hexdigest()
               for name in EXPORTS},
        limitations=['viewing_CSV_formula_escaped', 'raw_rows_not_unique_messages',
                     'source_times_offsets_IPs_and_unknowns_preserved',
                     'RETR_commands_not_unique_message_count',
                     'no_missing_action_IP_attribution'])
    (output / 'manifest.json').write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--account', required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.database, args.output, args.account)['counts']))
