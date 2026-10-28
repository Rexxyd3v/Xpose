import contextlib
import http.client
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from expose.cli.app import main
from expose.config import load_config
from expose.core.detector import Detector
from expose.core.git_scan import scan_history, scan_staged
from expose.core.scanner import Scanner
from expose.remote.github import parse_github_url
from expose.reports.formats import report_html, sarif
from expose.rules.loader import load_rules
from expose.state import baseline_ids, make_baseline, read_json

ENTRY = Path(__file__).resolve().parents[1] / 'xpose.py'
# Construct synthetic fixtures at runtime, so the source is safe to scan.
TOKEN = 'ghp_' + 'AbCd0123456789efGhIjKlMnOpQrStUvWxYz01'
TOKEN = TOKEN[:40]

class Workspace(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='xpose_test_')
        self.root = Path(self.temp.name)
        self.rules = load_rules()
    def tearDown(self):
        self.temp.cleanup()
    def scanner(self, **kwargs):
        return Scanner(self.rules, **kwargs)
    def cli(self, *args, cwd=None):
        return subprocess.run([sys.executable, str(ENTRY), *map(str,args)], cwd=cwd or self.root, capture_output=True, text=True, env={**os.environ, 'GIT_CEILING_DIRECTORIES':str(self.root.parent)}, timeout=30)
    def menu_cli(self, inputs, remote_source=None):
        script = 'import sys; sys.path.insert(0, ' + repr(str(ENTRY.parent)) + '); sys.stdin.isatty=lambda: True; from expose.cli import app; '
        if remote_source:
            script += 'import subprocess; app.clone_repo=lambda url,dest,full_history=False: subprocess.run(["git","clone","--no-hardlinks","--no-checkout",' + repr(str(remote_source)) + ',str(dest)],check=True,capture_output=True,timeout=20); '
        script += 'raise SystemExit(app.main())'
        return subprocess.run([sys.executable, '-c', script], input='\n'.join(inputs)+'\n', cwd=self.root, capture_output=True, text=True, encoding='utf-8', env={**os.environ, 'PYTHONUTF8':'1', 'GIT_CEILING_DIRECTORIES':str(self.root.parent)}, timeout=30)
    def git(self, *args):
        result = subprocess.run(['git', '-C', str(self.root), *args], capture_output=True, check=True, timeout=30)
        return result.stdout
    def repo(self):
        self.git('init')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'Xpose Test')
    def fixture(self):
        (self.root/'app.env').write_text('TOKEN=' + TOKEN + '\n', encoding='utf-8')

    def test_mask_every_output_and_stable_id(self):
        self.fixture()
        first = self.cli('scan', '.', '--format', 'json')
        self.assertEqual(first.returncode, 1, first.stderr)
        report = read_json(self.root/'report.json')
        finding = report['findings'][0]
        for output in (first.stdout, json.dumps(report), report_html(report), json.dumps(sarif(report))):
            self.assertNotIn(TOKEN, output)
        self.assertEqual(finding['file'], 'app.env')
        (self.root/'app.env').write_text('\n\nTOKEN=' + TOKEN, encoding='utf-8')
        second = self.scanner().scan(self.root)
        self.assertEqual(finding['id'], second[0]['id'])
        self.assertEqual(len(second), 1)  # report and .xpose are excluded

    def test_cli_reveal_never_saves_raw_credentials(self):
        self.fixture()
        result = self.cli('scan', '.', '--reveal')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(TOKEN, result.stdout)
        self.assertIn('Credential', result.stdout)
        self.assertIn('Fix', result.stdout)
        for path in (self.root/'report.json', self.root/'.xpose/latest.json', self.root/'.xpose/runs.json'):
            self.assertNotIn(TOKEN, path.read_text())
        report_result = self.cli('report')
        self.assertEqual(report_result.returncode, 0, report_result.stderr)
        self.assertIn('GitHub PAT', report_result.stdout)
        self.assertIn('app.env:1', report_result.stdout)
        self.assertNotIn(TOKEN, report_result.stdout)
        self.assertEqual(self.cli('scan', '.', '--reveal', '--quiet').returncode, 2)

    def test_show_all_findings_in_cli_and_explicit_limit(self):
        (self.root/'many.env').write_text('\n'.join('KEY=' + TOKEN for _ in range(23)))
        result = self.cli('scan', '.')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('many.env:23', result.stdout)
        limited = self.cli('scan', '.', '--limit', 2)
        self.assertNotIn('many.env:23', limited.stdout)
        self.assertIn('--limit 0', limited.stdout)
        self.cli('baseline')
        baseline = self.cli('scan', '.', '--baseline', '.xpose-baseline.json')
        self.assertEqual(baseline.returncode, 0)
        self.assertIn('many.env:23', baseline.stdout)

    def test_reveal_staged_and_history_values(self):
        self.repo()
        self.fixture()
        self.git('add', 'app.env')
        (self.root/'app.env').write_text('clean working tree')
        staged = self.cli('staged', '.', '--reveal')
        self.assertEqual(staged.returncode, 1, staged.stderr)
        self.assertIn(TOKEN, staged.stdout)
        self.git('commit', '-m', 'synthetic history')
        history = self.cli('history', '.', '--reveal')
        self.assertEqual(history.returncode, 1, history.stderr)
        self.assertIn(TOKEN, history.stdout)
        self.assertNotIn(TOKEN, (self.root/'report.json').read_text())

    def test_menu_colors_and_removed_local_first(self):
        from expose.cli import ui
        output = io.StringIO()
        with patch.object(ui, 'ENABLED', True), contextlib.redirect_stdout(output):
            ui.banner()
            ui.menu()
        self.assertNotIn('LOCAL-FIRST', output.getvalue())
        with patch.object(ui, 'ENABLED', True):
            self.assertIn(ui.color('[1]', 'primary'), output.getvalue())
            self.assertIn(ui.color('[8]', 'accent'), output.getvalue())
        self.assertIn('Latest report', output.getvalue())

    def test_interactive_scan_selects_reveal(self):
        from expose.cli.app import interactive
        from expose.cli import ui
        with patch.object(ui, 'banner'), patch.object(ui, 'menu'), patch.object(ui, 'prompt', side_effect=['1', '.', '', '', '0']), patch('expose.cli.app.main') as run:
            self.assertEqual(interactive(), 0)
        run.assert_called_once_with(['scan', '.', '--reveal'], session={})

    def test_help_menu_stays_visible_until_enter_real_process(self):
        result = self.menu_cli(['7', '', '0'])
        self.assertEqual(result.returncode, 0, result.stderr)
        output = result.stdout
        self.assertIn('HELP / HOW TO USE XPOSE', output)
        help_start = output.index('HELP / HOW TO USE XPOSE')
        pause = output.index('Press Enter to return to menu', help_start)
        next_menu = output.index('Choose [0-8]', pause)
        self.assertLess(help_start, pause)
        self.assertLess(pause, next_menu)
        self.assertNotIn('Choose a number from 0 to 8', output)
        self.assertEqual(self.cli('help').returncode, 0)

    def test_scan_report_review_use_same_target_real_menu(self):
        target = self.root/'another-project'
        target.mkdir()
        (target/'app.env').write_text(TOKEN)
        result = self.menu_cli(['1', str(target), 'y', '', '8', '', '5', '', '', '7', '', '0'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(TOKEN, result.stdout)
        self.assertGreaterEqual(result.stdout.count('app.env:1'), 3)
        self.assertIn('HELP / HOW TO USE XPOSE', result.stdout)
        self.assertNotIn('No JSON report available', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertTrue((target/'.xpose/latest.json').is_file())

    def test_staged_history_invalid_choice_and_errors_real_menu(self):
        self.repo()
        self.fixture()
        self.git('add', 'app.env')
        self.git('commit', '-m', 'synthetic history')
        (self.root/'new.env').write_text(TOKEN)
        self.git('add', 'new.env')
        result = self.menu_cli(['invalid', '3', str(self.root), 'n', '', '4', str(self.root), 'n', '', '1', 'missing-file', 'n', '', '7', '', '0'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Choose a number from 0 to 8', result.stdout)
        self.assertIn('new.env:1', result.stdout)
        self.assertIn('app.env:1', result.stdout)
        self.assertIn('Scan target does not exist', result.stderr)
        self.assertIn('HELP / HOW TO USE XPOSE', result.stdout)

    def test_invalid_argument_does_not_exit_interactive_menu(self):
        result = self.menu_cli(['1', '--not-a-path', 'n', '', '7', '', '0'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Invalid input', result.stdout)
        self.assertIn('HELP / HOW TO USE XPOSE', result.stdout)

    def test_dashboard_menu_opens_last_scan_state(self):
        from expose.cli.app import interactive
        from expose.cli import ui
        target = self.root/'another-project'
        target.mkdir()
        (target/'app.env').write_text(TOKEN)
        with patch.object(ui, 'banner'), patch.object(ui, 'menu'), patch.object(ui, 'prompt', side_effect=['1', str(target), 'n', '', '6', '', '0']), patch('expose.dashboard.serve') as serve, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(interactive(), 0)
        serve.assert_called_once_with(str(target/'.xpose'), 8765, open_browser=True)

    def test_empty_review_and_non_git_folder_explain_outcome(self):
        (self.root/'clean.txt').write_text('hello')
        self.assertEqual(self.cli('scan', '.').returncode, 0)
        review = self.cli('review')
        self.assertEqual(review.returncode, 0)
        self.assertIn('No findings match this review', review.stdout)
        staged = self.cli('staged', '.')
        self.assertEqual(staged.returncode, 2)
        self.assertIn('not an accessible Git repository', staged.stderr)

    def test_dashboard_busy_port_explains_fix(self):
        import errno
        from expose.dashboard import serve
        with patch('expose.dashboard.ThreadingHTTPServer', side_effect=OSError(errno.EADDRINUSE, 'in use')):
            with self.assertRaisesRegex(ValueError, 'already in use'):
                serve(self.root, 8765)

    def test_remote_scan_and_report_menu_with_local_clone_fixture(self):
        self.repo()
        self.fixture()
        self.git('add', 'app.env')
        self.git('commit', '-m', 'synthetic remote fixture')
        result = self.menu_cli(['2', 'example/repo', 'y', '', '8', '', '0'], remote_source=self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(TOKEN, result.stdout)
        self.assertGreaterEqual(result.stdout.count('app.env:1'), 2)
        self.assertNotIn('Xpose:', result.stderr)

    def test_remote_failure_explained_without_login_prompt(self):
        from expose.remote.github import clone_repo
        failure = subprocess.CompletedProcess([], 128, b'', b'fatal: Repository not found')
        with patch('expose.remote.github.subprocess.run', return_value=failure) as run:
            with self.assertRaisesRegex(ValueError, 'repository is not accessible'):
                clone_repo('example/missing', self.root/'clone')
        self.assertEqual(run.call_args.kwargs['stdin'], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs['env']['GIT_TERMINAL_PROMPT'], '0')

    def test_github_urls_automatically_select_remote_mode(self):
        url = 'https://github.com/kopicchino/cofm.git'
        for command in ('scan', 'history'):
            argv = [command, url, '--reveal']
            if command == 'history':
                argv += ['--max-commits', '5', '--revision', 'main']
            with patch('expose.cli.app.run_scan', return_value=0) as run:
                self.assertEqual(main(argv), 0)
                args = run.call_args.args[0]
                self.assertEqual(args.command, 'remote')
                self.assertEqual(args.url, url)
                self.assertEqual(args.history, command == 'history')
                self.assertTrue(args.reveal)
                self.assertEqual(args.max_commits, 5 if command == 'history' else 0)
                self.assertEqual(args.revision, 'main' if command == 'history' else '--all')

    def test_remote_staged_target_explains_local_requirement(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output), patch('expose.cli.app.run_scan') as run:
            self.assertEqual(main(['staged', 'https://github.com/kopicchino/cofm.git']), 2)
            run.assert_not_called()
        self.assertIn('Staged changes exist only in a local repository', output.getvalue())
        self.assertIn('xpose remote URL', output.getvalue())

    def test_existing_local_target_keeps_requested_mode(self):
        for command in ('scan', 'history', 'staged'):
            with patch('expose.cli.app.run_scan', return_value=0) as run:
                self.assertEqual(main([command, str(self.root)]), 0)
                self.assertEqual(run.call_args.args[0].command, command)

    def test_placeholders_uris_overlap_and_entropy(self):
        detector = Detector(self.rules)
        self.assertEqual(detector.find_secrets('api_key="your_placeholder_secret_here"'), [])
        self.assertEqual(detector.find_secrets('postgres://localhost:5432/app'), [])
        self.assertEqual(len(detector.find_secrets('postgres://user:' + 'password@localhost/app')), 1)
        self.assertEqual(len(detector.find_secrets('postgres://user:' + 'S3cUr3mIxed9' + '@localhost/app')), 1)
        findings = detector.find_secrets('api_key="' + TOKEN + '"')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['rule'], 'GitHub PAT')
        self.assertNotIn(TOKEN, findings[0]['context'])
        d = Detector({'rules':[{'name':'low','pattern':r'(?P<secret>[a-z]{16})','severity':'HIGH','min_entropy':4}]})
        self.assertFalse(d.find_secrets('abababababababab'))

    def test_passwords_tokens_identifiers_and_authorization(self):
        sample_password = ''.join(('S3cur3', '!Pass9'))
        sample_token = ''.join(('access_', 'AbcD1234efGH5678ijkl'))
        content = '\n'.join([
            'DB_' + 'USER' + 'NAME=alice',
            'DB_' + 'PASSWORD=' + sample_password,
            json.dumps({'client' + '_secret': sample_token}),
            'Authorization' + ': Bearer ' + sample_token,
            '<pass' + 'word>' + sample_password + '</password>',
            'redis://alice:' + sample_password + '@localhost:6379/0',
            'SMTP_' + 'PASS' + 'WORD="hello world 123"',
        ])
        scanner = Scanner(self.rules, retain_secrets=True)
        scanner.scan_content(content.encode(), 'settings.env')
        names = {f['rule'] for f in scanner.findings}
        self.assertTrue({'Login Identifier', 'Password', 'Client or Signing Secret', 'HTTP Authorization', 'XML Password', 'Credential URI'} <= names)
        self.assertIn(sample_password, scanner.revealed.values())
        self.assertIn('alice', scanner.revealed.values())
        self.assertIn('hello world 123', scanner.revealed.values())
        self.assertNotIn(sample_password, json.dumps(scanner.findings))
        self.assertNotIn(sample_token, json.dumps(scanner.findings))
        self.assertEqual(next(f['line'] for f in scanner.findings if f['rule'] == 'HTTP Authorization'), 4)

    def test_real_weak_passwords_and_dynamic_references(self):
        detector = Detector(self.rules)
        for value in ('password', 'changeme', '11111111', 'abc'):
            self.assertTrue(detector.find_secrets('DB_' + 'PASSWORD=' + value), value)
        for value in ('${DB_PASSWORD}', 'os.environ.get("DB_PASSWORD")', 'process.env.DB_PASSWORD', 'null', '""', 'your_password_here'):
            self.assertFalse(detector.find_secrets('DB_' + 'PASSWORD=' + value), value)

    def test_complete_multiline_private_key_reveal_and_masking(self):
        body = 'MIIE' + 'SyntheticNotARealKey1234567890'
        pem = '-----BEGIN RSA ' + 'PRIVATE KEY-----\n' + body + '\n-----END RSA ' + 'PRIVATE KEY-----'
        scanner = Scanner(self.rules, retain_secrets=True)
        scanner.scan_content(('heading\n' + pem + '\nafter\nTOKEN=' + TOKEN).encode(), 'credentials.pem')
        private = next(f for f in scanner.findings if f['rule'] == 'Private Key')
        self.assertEqual(private['line'], 2)
        self.assertEqual(scanner.revealed[private['id']], pem)
        self.assertEqual(private['context'], '[REDACTED]')
        self.assertNotIn(body, json.dumps(scanner.findings))
        github = next(f for f in scanner.findings if f['rule'] == 'GitHub PAT')
        self.assertEqual(github['line'], 6)

    def test_unquoted_api_values_hashes_and_basic_auth(self):
        sample = ''.join(('AbcD1234', 'efGH5678ijkl'))
        bcrypt = '$2b$12$' + 'AbcD0123456789efGhIjKlMnOpQrStUvWxYz./' + 'abcdEFG1234567890'
        bcrypt = bcrypt[:60]
        argon = '$argon2id$' + 'v=19$m=65536,t=3,p=4$YWJjZGVmZ2hpamts$YWJjZGVmZ2hpamts'
        text = '\n'.join(['API_' + 'KEY=' + sample, bcrypt, argon, 'Authorization' + ': Basic dXNlcjpwYXNz'])
        scanner = Scanner(self.rules, retain_secrets=True)
        scanner.scan_content(text.encode(), 'credentials.env')
        names = {f['rule'] for f in scanner.findings}
        self.assertTrue({'API Credential', 'Bcrypt Password Hash', 'Argon2 Password Hash', 'HTTP Authorization'} <= names)
        self.assertNotIn(sample, json.dumps(scanner.findings))
        self.assertIn(sample, scanner.revealed.values())

    def test_blank_password_does_not_consume_next_line(self):
        detector = Detector(self.rules)
        self.assertFalse(detector.find_secrets('DB_' + 'PASS' + 'WORD=\nordinary_text_on_next_line'))
        self.assertFalse(detector.find_secrets('on_' + 'secret=values.append'))

    def test_javascript_property_and_variable_references_are_not_credentials(self):
        cases = [
            'email: user.email,',
            'const user = auth.currentUser;',
            'const password = suppliedPassword;',
            'const client_secret = session.clientSecret;',
            'const user = auth?.currentUser;',
            'email: user["email"],',
            'const { email: userEmail } = profile;',
            'password: form.password.value,',
            'password: getPassword(),',
            'const password = `prefix-${user.password}`;',
        ]
        for file in ('js/auth.js', 'js/profile.js', 'auth.ts', 'form.tsx', 'auth.mjs'):
            for code in cases:
                with self.subTest(file=file, code=code):
                    scanner = self.scanner(retain_secrets=True)
                    scanner.scan_content(code.encode(), file)
                    self.assertEqual(scanner.findings, [])
                    self.assertEqual(scanner.revealed, {})

    def test_code_literals_and_unquoted_config_credentials_still_detected(self):
        literal = ''.join(('Mixed9!', 'literal.Pass'))
        detector = Detector(self.rules)
        for quote in ('"', "'", '`'):
            code = 'const password = ' + quote + literal + quote + ';'
            scanner = self.scanner(retain_secrets=True)
            scanner.scan_content(code.encode(), 'auth.js')
            self.assertTrue(scanner.findings)
            self.assertIn(literal, scanner.revealed.values())
            self.assertNotIn(literal, json.dumps(scanner.findings))
        for file in ('.env', 'settings.env', 'settings.yaml', 'settings.ini'):
            for value in ('user.email', 'auth.currentUser', 'alice.smith', '12345678'):
                with self.subTest(file=file, value=value):
                    scanner = self.scanner(retain_secrets=True)
                    scanner.scan_content(('DB_' + 'PASSWORD=' + value).encode(), file)
                    self.assertTrue(scanner.findings)
                    self.assertIn(value, scanner.revealed.values())
        quoted = detector.find_secrets('password=' + '"process.env.SECRET"', source_path='auth.js')
        self.assertTrue(quoted)  # Quoted text is a literal, not an environment lookup.

    def test_real_secret_beside_reference_stays_visible_and_masked(self):
        literal = ''.join(('Mixed9!', 'literal.Pass'))
        text = 'const credentials = { email: user.email, password: "' + literal + '" };'
        scanner = self.scanner(retain_secrets=True)
        scanner.scan_content(text.encode(), 'auth.js')
        self.assertEqual([f['rule'] for f in scanner.findings], ['Password'])
        self.assertIn('email: user.email', scanner.findings[0]['context'])
        self.assertNotIn(literal, scanner.findings[0]['context'])
        self.assertEqual(list(scanner.revealed.values()), [literal])

    def test_multiple_overlapping_masks(self):
        line = 'api_key="' + TOKEN + '" OTHER=' + TOKEN
        findings = Detector(self.rules).find_secrets(line)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(TOKEN not in f['context'] for f in findings))

    def test_skipped_errors_and_size_are_visible(self):
        (self.root/'bad.txt').write_bytes(b'\xff\xfeabc')
        (self.root/'binary.bin').write_bytes(b'\0abc')
        (self.root/'large.txt').write_bytes(b'x'*100)
        result = self.cli('scan', '.', '--max-file-size', '90', '-q')
        self.assertEqual(result.returncode, 2)
        report = read_json(self.root/'report.json')
        self.assertFalse(report['complete'])
        self.assertEqual(len(report['errors']), 1)
        self.assertEqual(len(report['skipped']), 2)

    def test_exclusions_and_custom_config(self):
        (self.root/'ignored').mkdir()
        (self.root/'ignored'/'key.txt').write_text(TOKEN)
        (self.root/'.xpose.toml').write_text('exclude = ["ignored/**"]\n[[rules]]\nname="Internal"\npattern=\'internal_(?P<secret>[A-Za-z0-9]{20})\'\nseverity="HIGH"\n')
        (self.root/'internal.txt').write_text('internal_' + 'AbcD1234efGH5678ijkl')
        result = self.cli('scan', '.')
        self.assertEqual(result.returncode, 1, result.stderr)
        report = read_json(self.root/'report.json')
        self.assertEqual([f['rule'] for f in report['findings']], ['Internal'])

    def test_baseline_dismissal_restore(self):
        self.fixture()
        self.cli('scan', '.')
        finding = read_json(self.root/'report.json')['findings'][0]
        self.assertEqual(self.cli('baseline').returncode, 0)
        baseline = (self.root/'.xpose-baseline.json').read_text()
        self.assertNotIn(TOKEN, baseline)
        self.assertEqual(self.cli('scan', '.', '--baseline', '.xpose-baseline.json').returncode, 0)
        result = self.cli('review', '--id', finding['id'][:12], '--reason', 'synthetic test credential')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.cli('scan', '.').returncode, 0)
        self.assertEqual(self.cli('review', '--id', finding['id'], '--restore').returncode, 0)
        self.assertEqual(self.cli('scan', '.').returncode, 1)

    def test_exit_threshold_and_missing_target(self):
        self.fixture()
        self.assertEqual(self.cli('scan', '.', '--fail-on', 'CRITICAL').returncode, 0)
        self.assertEqual(self.cli('scan', '.', '--min-severity', 'CRITICAL').returncode, 1)
        self.assertEqual(self.cli('scan', 'does-not-exist').returncode, 2)
        self.assertEqual(self.cli('scan', '.', '--baseline', 'missing.json').returncode, 2)

    def test_actual_staged_content_and_unborn_repo(self):
        self.repo()
        self.fixture()
        self.git('add', 'app.env')
        (self.root/'app.env').write_text('clean working tree')
        scanner = self.scanner()
        scan_staged(scanner, self.root)
        self.assertEqual(len(scanner.findings), 1)
        self.assertEqual(self.cli('staged', '.').returncode, 1)
        self.git('add', 'app.env')
        (self.root/'app.env').write_text(TOKEN)
        scanner = self.scanner()
        scan_staged(scanner, self.root)
        self.assertEqual(scanner.findings, [])

    def test_deleted_secrets_history_dedup_and_ranges(self):
        self.repo()
        self.fixture()
        self.git('add', 'app.env')
        self.git('commit', '-m', 'synthetic fixture')
        self.git('commit', '--allow-empty', '-m', 'unchanged')
        self.git('rm', 'app.env')
        self.git('commit', '-m', 'remove fixture')
        scanner = self.scanner()
        self.assertEqual(scan_history(scanner, self.root), 3)
        self.assertEqual(len(scanner.findings), 1)
        self.assertEqual(len(scanner.findings[0]['commit']), 40)
        scanner = self.scanner()
        self.assertEqual(scan_history(scanner, self.root, 'HEAD~1..HEAD'), 1)
        self.assertFalse(scanner.findings)

    def test_hook_install_preserves_existing_and_blocks(self):
        self.repo()
        result = self.cli('hook')
        self.assertEqual(result.returncode, 0, result.stderr)
        hook = self.root/'.git/hooks/pre-commit'
        original = hook.read_bytes()
        self.assertEqual(self.cli('hook').returncode, 2)
        self.assertEqual(hook.read_bytes(), original)
        self.fixture()
        self.git('add', 'app.env')
        result = subprocess.run(['git', '-C', str(self.root), 'commit', '-m', 'should block'], capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(TOKEN.encode(), result.stdout + result.stderr)

    def test_invalid_configuration_and_regex(self):
        for text in ('max_file_size = -1', 'exclude = "wrong"', 'unknown = 1', 'fail_on = "extreme"', '[[rules]]\nname="bad"\npattern="["\nseverity="HIGH"'):
            (self.root/'.xpose.toml').write_text(text)
            self.assertEqual(self.cli('scan', '.').returncode, 2, text)

    def test_html_escapes_source_and_sarif_paths(self):
        (self.root/'a space.txt').write_text('<script>alert(1)</script> ' + TOKEN)
        self.cli('scan', '.')
        report = read_json(self.root/'report.json')
        self.assertNotIn('<script>alert(1)</script>', report_html(report))
        value = sarif(report)
        location = value['runs'][0]['results'][0]['locations'][0]['physicalLocation']
        self.assertEqual(location['artifactLocation']['uri'], 'a%20space.txt')
        self.assertEqual(location['region']['startLine'], 1)

    def test_rule_playground_masks_sample(self):
        self.fixture()
        result = self.cli('test-rule', '--pattern', r'ghp_[A-Za-z0-9]{36}', '--file', 'app.env')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('1 matches', result.stdout)
        self.assertNotIn(TOKEN, result.stdout)

    def test_remote_cleanup_even_on_error(self):
        paths = []
        def clone(url, dest, full_history=False):
            paths.append(Path(dest))
            raise ValueError('simulated clone failure')
        with patch('expose.cli.app.clone_repo', side_effect=clone), contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['remote', 'example/repo', '--no-save']), 2)
        self.assertTrue(paths)
        self.assertFalse(paths[0].exists())

    def test_github_target_validation(self):
        self.assertEqual(parse_github_url('https://github.com/user/digit.git/'), 'user/digit')
        self.assertEqual(parse_github_url('git@github.com:user/widget.git'), 'user/widget')
        for value in ('https://evil.invalid/user/repo', 'https://github.com/user/repo/tree/main', 'https://token@github.com/user/repo'):
            with self.assertRaises(ValueError):
                parse_github_url(value)

    def test_dashboard_routes_and_host_protection(self):
        from http.server import ThreadingHTTPServer
        from expose import dashboard
        self.fixture()
        self.cli('scan', '.')
        ready = threading.Event()
        servers = []
        def factory(address, handler):
            server = ThreadingHTTPServer(address, handler)
            servers.append(server)
            ready.set()
            return server
        with patch('expose.dashboard.ThreadingHTTPServer', side_effect=factory), contextlib.redirect_stdout(io.StringIO()):
            thread = threading.Thread(target=dashboard.serve, args=(self.root/'.xpose', 0), daemon=True)
            thread.start()
            self.assertTrue(ready.wait(5))
            server = servers[0]
            try:
                connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                for route in ('/', '/api', '/report'):
                    connection.request('GET', route)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertNotIn(TOKEN, response.read().decode())
                    self.assertEqual(response.getheader('Cache-Control'), 'no-store')
                connection.request('GET', '/api', headers={'Host':'attacker.invalid'})
                response = connection.getresponse()
                self.assertEqual(response.status, 403)
                response.read()
                connection.request('GET', '/../../README.md')
                response = connection.getresponse()
                self.assertEqual(response.status, 404)
                response.read()
                connection.close()
            finally:
                server.shutdown()
                thread.join(5)

    def test_banner_exact_art_and_gradient_fallback(self):
        from expose.cli import ui
        with patch.object(ui, 'ENABLED', True), patch.dict(os.environ, {'COLORTERM':'truecolor'}):
            rendered = ui.gradient(ui.BANNER)
            self.assertIn('\033[38;2;', rendered)
            self.assertIn('\033[0m', rendered)
            import re
            self.assertEqual(re.sub(r'\x1b\[[0-9;]*m', '', rendered), ui.BANNER)
        with patch.object(ui, 'ENABLED', False):
            self.assertEqual(ui.gradient(ui.BANNER), ui.BANNER)

    def test_remote_object_scan_and_success_cleanup(self):
        self.repo()
        self.fixture()
        self.git('add', 'app.env')
        self.git('commit', '-m', 'synthetic remote')
        destinations = []
        def clone(url, dest, full_history=False):
            destinations.append(Path(dest))
            subprocess.run(['git', 'clone', '--no-hardlinks', '--no-checkout', str(self.root), str(dest)], check=True, capture_output=True, timeout=30)
        output = self.root/'remote.json'
        with patch('expose.cli.app.clone_repo', side_effect=clone), contextlib.redirect_stdout(io.StringIO()):
            result = main(['remote', 'example/repo', '--no-save', '--output', str(output)])
        self.assertEqual(result, 1)
        report = read_json(output)
        self.assertEqual(report['findings'][0]['file'], 'app.env')
        self.assertNotIn(TOKEN, json.dumps(report))
        self.assertFalse(destinations[0].exists())

if __name__ == '__main__':
    unittest.main()
