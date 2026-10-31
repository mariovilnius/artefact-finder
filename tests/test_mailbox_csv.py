import csv
import hashlib
import importlib.util
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/mail-log-triage/scripts'
spec = importlib.util.spec_from_file_location('mailbox_csv', SCRIPTS / 'mailbox_csv.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MailboxCSVTests(unittest.TestCase):
    def fixture(self, root):
        path = root / 'synthetic.sqlite'
        with closing(sqlite3.connect(path)) as db:
            db.execute('CREATE TABLE events(account TEXT,kind TEXT,retr_commands INTEGER,'
                       'del_counter INTEGER,second INTEGER,time TEXT,ip TEXT,file TEXT,'
                       'line INTEGER,raw TEXT)')
            rows = [
                ('a@example.test', 'logout', 2, 0, 1, 1),
                ('a@example.test', 'logout', 0, 1, 2, 2),
                ('a@example.test', 'logout', 0, 0, 3, 3),
                ('a@example.test', 'mail_expunge', 0, 0, None, 4),
                ('b@example.test', 'logout', 8, 0, 1, 5),
                ('b@example.test', 'logout', 0, 9, 2, 6),
                ('b@example.test', 'mail_copy', 0, 0, 3, 7),
            ]
            for account, kind, retr, deleted, second, line in rows:
                db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?)',
                           (account, kind, retr, deleted, second,
                            '2026-01-01T00:00:01+02:00', None,
                            'synthetic.txt', line, '=synthetic evidence'))
            db.commit()
        return path

    def read(self, path):
        with path.open(encoding='utf-8-sig', newline='') as f:
            return list(csv.DictReader(f))

    def test_disjunction_never_leaks_another_mailbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); database = self.fixture(root)
            before = hashlib.sha256(database.read_bytes()).hexdigest()
            for account, expected in [('a@example.test', [1, 2]),
                                      ('b@example.test', [5, 6])]:
                output = root / account
                result = m.run(database, output, account)
                rows = self.read(output / 'positive-retr-or-deletion.csv')
                self.assertEqual([int(r['line']) for r in rows], expected)
                for name in m.EXPORTS:
                    self.assertTrue(all(r['account'] == account
                                        for r in self.read(output / name)))
                self.assertEqual(result['counts']['mail-actions.csv'], 1)
            self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)

    def test_preserves_ambiguous_time_unknown_IP_and_viewing_safety(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); database = self.fixture(root)
            m.run(database, root / 'out', 'a@example.test')
            row = self.read(root / 'out/mail-actions.csv')[0]
            self.assertEqual(row['line'], '4')
            self.assertEqual(row['second'], '')
            self.assertEqual(row['ip'], '')
            self.assertEqual(row['time'], '2026-01-01T00:00:01+02:00')
            self.assertEqual(row['raw'], "'=synthetic evidence")

    def test_literal_account_empty_results_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); database = self.fixture(root)
            result = m.run(database, root / 'out', "a' OR 1=1 --")
            self.assertEqual(set(result['counts'].values()), {0})
            with self.assertRaises(FileExistsError):
                m.run(database, root / 'out', 'a@example.test')
            with self.assertRaises(ValueError):
                m.run(database, root / 'empty', ' ')


if __name__ == '__main__':
    unittest.main()
