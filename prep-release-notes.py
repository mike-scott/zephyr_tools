# Copyright (c) Open Source Foundries Ltd 2018
# Copyright (c) Foundries.io Ltd 2019
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
import textwrap

from west.commands import WestCommand
from west import manifest
from west import log

from pygit2_helpers import repo_commits, commit_shortsha, commit_shortlog

# Projects we care about for the purposes of release notes.
ZMP_PROJECTS = ['west', 'zephyr', 'mcuboot', 'dm-lwm2m']


class ZMPReleaseNotes(WestCommand):
    def __init__(self):
        super().__init__(
            'zmp-release-notes',
            # Keep this in sync with the string in west-commands.yml.
            'print ZmP release notes',
            textwrap.dedent('''\
            Print release notes information given two frozen west manifests:

            - an "old" manifest from the previous ZmP update
            - a "new" manifest which is the next pending ZmP update

            '''),
            accepts_unknown_args=False)

    def do_add_parser(self, parser_adder):
        parser = parser_adder.add_parser(
            self.name,
            help=self.help,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=self.description)

        parser.add_argument('old_manifest', help='old frozen west manifest')
        parser.add_argument('new_manifest', help='new frozen west manifest')

        return parser

    def do_run(self, args, ignored):
        old = self._load_manifest(args.old_manifest)
        new = self._load_manifest(args.new_manifest)

        print_notes(old, new)

    def _load_manifest(self, path):
        try:
            return manifest.Manifest.from_file(path)
        except manifest.MalformedManifest:
            print(path, 'is a malformed manifest!', file=sys.stderr)
            sys.exit(1)
        except manifest.MalformedConfig:
            log.err("can't load manifest due to bad configuration settings")
            raise
            sys.exit(1)


def zmp_project_data(manifest):
    ret = {}
    for p in list(manifest.projects) + [manifest.west_project]:
        name = p.name
        if name in ZMP_PROJECTS:
            ret[name] = p
    return ret


def print_notes(start_manifest, end_manifest):
    # Get 'revision' and 'path' dicts for each project we track in
    # each pinned manifest, keyed by name.
    start_data = zmp_project_data(start_manifest)
    end_data = zmp_project_data(end_manifest)

    notes_metadata = {}
    for p in ZMP_PROJECTS:
        start_rev = start_data[p].revision
        end_rev = end_data[p].revision
        # end should have the entire history; start might be gone.
        path = end_data[p].abspath
        commits = repo_commits(path, start_rev, end_rev)
        ncommits = len(commits)

        if ncommits >= 2:
            sc, ec = commits[-1], commits[0]
            changes = '''\
{} patches total:

- start commit: {} ("{}").
- end commit: {} ("{}").'''.format(ncommits, commit_shortsha(sc),
                                   commit_shortlog(sc), commit_shortsha(ec),
                                   commit_shortlog(ec))
        elif ncommits == 1:
            changes = 'One new commit: {} ("{}").'.format(
                commit_shortsha(commits[0]),
                commit_shortlog(commits[0]))
        else:
            changes = 'No changes.'

        notes_metadata[p] = {
            'path': path,  # assume it stays the same
            'start_revision': start_rev,
            'end_revision': end_rev,
            'commits': commits,
            'changes': changes,
            }

    print('''\
## West

{}

## Zephyr

{}

## MCUboot

{}

## dm-lwm2m

{}
'''.format(*[notes_metadata[p]['changes'] for p in ZMP_PROJECTS]))
