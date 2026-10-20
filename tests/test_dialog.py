"""Offline regression tests for dialog terminal output and field captures."""
import os
import subprocess
import unittest
from unittest.mock import patch
from zwhois_lib import cli

class DialogTests(unittest.TestCase):
    def test_nonterminal_fails_cleanly(self):
        with patch.object(cli.shutil, 'which', return_value='/usr/bin/dialog'), \
                patch.object(cli.sys.stdin, 'isatty', return_value=False):
            self.assertEqual(cli.dialog_ui({}), 2)

    def test_dialog_menu_is_visible_and_exit_is_recognized(self):
        commands=[]
        def fake_run(cmd, **kwargs):
            commands.append((cmd, kwargs))
            self.assertNotIn('stderr', kwargs)
            self.assertNotIn('stdout', kwargs)
            self.assertEqual(kwargs['pass_fds'], (int(cmd[2]),))
            os.write(int(cmd[2]), b'5\n')
            return subprocess.CompletedProcess(cmd, 0)
        with patch.object(cli.shutil, 'which', side_effect=lambda x: '/fake/dialog' if x == 'dialog' else None), \
                patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli.sys.stderr, 'isatty', return_value=True), \
                patch.object(cli.subprocess, 'run', side_effect=fake_run):
            self.assertEqual(cli.dialog_ui({}), 0)
        self.assertEqual(len(commands), 1)
        self.assertIn('--menu', commands[0][0])

    def test_edit_select_run_and_return_to_menu(self):
        states = [('--menu','1'), ('--inputbox','secure.example.com'), ('--menu','2'),
                  ('--checklist','-H\n-ns'), ('--menu','3'), ('--textbox',''),
                  ('--menu','4'), ('--textbox',''), ('--menu','5')]
        observed=[]
        def fake_run(cmd, **kwargs):
            expected, selection = states[len(observed)]
            self.assertIn(expected, cmd)
            observed.append(expected)
            os.write(int(cmd[2]), selection.encode())
            return subprocess.CompletedProcess(cmd, 0)
        with patch.object(cli.shutil, 'which', return_value='/fake/dialog'), \
                patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                patch.object(cli.sys.stderr, 'isatty', return_value=True), \
                patch.object(cli.subprocess, 'run', side_effect=fake_run), \
                patch.object(cli, 'audit', return_value='FAKE OFFLINE REPORT') as mock_audit:
            self.assertEqual(cli.dialog_ui({}), 0)
        self.assertEqual(len(observed), len(states))
        self.assertEqual(mock_audit.call_args.args[0], 'secure.example.com')
        flags=mock_audit.call_args.args[1]
        self.assertTrue(flags[2]) # Hosting
        self.assertTrue(flags[6]) # Nameservers
        self.assertFalse(flags[7]) # Full

if __name__ == '__main__':
    unittest.main()
