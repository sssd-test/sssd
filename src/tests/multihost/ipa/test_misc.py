""" Miscellaneous IPA Bug Automations

:requirement: IDM-SSSD-REQ: Testing SSSD in IPA Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""

import pytest
import time
from sssd.testlib.common.utils import sssdTools, SSHClient
from sssd.testlib.common.exceptions import SSSDException
import re


@pytest.mark.usefixtures('default_ipa_users', 'reset_password')
@pytest.mark.tier1
class Testipabz(object):
    """ IPA BZ Automations """
    def test_anonymous_pkinit_for_fast(self, multihost, backupsssdconf):
        """
        :title: Allow SSSD to use anonymous pkinit for FAST
        :id: 4a3ecc11-0d5b-4dce-bd08-5b1f47164b44
        :customerscenario: True
        :description:
         For SSSD to use FAST a Kerberos keytab and service principal must
         exist. SSSD to be enhanced to allow for the use of anonymous pkinit
         to create the FAST session.
        :steps:
          1. Setup a IPA server/client with default setting.
          2. Call anonymous processing using #kinit -n.
          3. Set 'krb5_fast_use_anonymous_pkinit = True' in sssd.conf.
          4. Login to the IPA user.
          5. Check a ccache file with the FAST armor ticket.
        :expectedresults:
          1. Successfully setup the IPA server/client.
          2. Successfully called anonymous processing.
          3. Successfully set the option in sssd.conf.
          4. Successfully logged in to IPA user.
          5. Successfully get a ccache file with the FAST armor ticket
        :bugzilla:
        https://bugzilla.redhat.com/show_bug.cgi?id=1859751
        """
        time.sleep(10000000)
        sssd_client = sssdTools(multihost.client[0])
        multihost.client[0].run_command('yum update -y sssd')
        domain_name = f'domain/{sssd_client.get_domain_section_name()}'
        add_anony_pkinit = {'krb5_fast_use_anonymous_pkinit': 'True'}
        sssd_client.sssd_conf(domain_name, add_anony_pkinit)
        sssd_client.clear_sssd_cache()
        cmd_kinit = multihost.client[0].run_command('kinit -n')
        assert cmd_kinit.returncode == 0
        ssh = SSHClient(multihost.client[0].ip,
                        username='foobar0', password='Secret123')
        ssh.close()
        cmd_klist = f'klist /var/lib/sss/db/fast_ccache_{sssd_client.get_domain_section_name().upper()}'
        output = multihost.client[0].run_command(cmd_klist).stdout_text
        principal = 'WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS'
        assert principal in output

    def test_anonymous_pkinit_for_fast_false(self, multihost, backupsssdconf):
        """
        :title: Negative test for allow SSSD to use anonymous pkinit for FAST
        :id: de823122-af88-41f6-b762-63083fccaa87
        :customerscenario: True
        :description:
         For SSSD to use FAST a Kerberos keytab and service principal must
         exist. SSSD to be enhanced to allow for the use of anonymous pkinit
         to create the FAST session. With
         'krb5_fast_use_anonymous_pkinit = False' the ccache will have a
         ticket for the host principal.
        :steps:
          1. Setup a IPA server/client with default setting.
          2. Call anonymous processing using #kinit -n.
          3. Set 'krb5_fast_use_anonymous_pkinit = False' in sssd.conf.
          4. Login to the IPA user.
          5. Check a ccache file for the host principal.
        :expectedresults:
          1. Successfully setup the IPA server/client.
          2. Successfully called anonymous processing.
          3. Successfully set the option in sssd.conf.
          4. Successfully logged in to IPA user.
          5. Successfully get a ccache file with the host principal.
        :bugzilla:
        https://bugzilla.redhat.com/show_bug.cgi?id=1859751
        """
        sssd_client = sssdTools(multihost.client[0])
        multihost.client[0].run_command('yum update -y sssd')
        domain_section = sssd_client.get_domain_section_name()
        domain_name = f'domain/{domain_section}'
        add_anony_pkinit = {'krb5_fast_use_anonymous_pkinit': 'False'}
        sssd_client.sssd_conf(domain_name, add_anony_pkinit)
        sssd_client.clear_sssd_cache()
        cmd_kinit = multihost.client[0].run_command('kinit -n')
        assert cmd_kinit.returncode == 0
        ssh = SSHClient(multihost.client[0].ip,
                        username='foobar1', password='Secret123')
        ssh.close()
        cmd_klist = f'klist /var/lib/sss/db/fast_ccache_{domain_section.upper()}'
        output = multihost.client[0].run_command(cmd_klist).stdout_text
        principal = re.compile(rf'principal:.host.{multihost.client[0].sys_hostname}@{domain_section.upper()}')
        assert principal.search(output)
