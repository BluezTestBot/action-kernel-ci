#!/usr/bin/env python3
import os
import sys
import argparse
import logging
import subprocess
import configparser
import requests
import re
import smtplib
import email.utils
from enum import Enum
from github import Github
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

# Globals
logger = None
config = None

github_repo = None
github_pr = None
github_commits = None

pw_sid = None
pw_series = None

src_dir = None
bluez_dir = None
output_dir = None

test_suite = {}

# Test Runner Context
test_runner_context = None

PW_BASE_URL = "https://patchwork.kernel.org/api/1.1"

EMAIL_MESSAGE = '''This is automated email and please do not reply to this email!

Dear submitter,

Thank you for submitting the patches to the linux bluetooth mailing list.
This is a CI test results with your patch series:
PW Link:{}

---Test result---

{}

---
Regards,
Linux Bluetooth

'''

TEST_REPORT =  '''##############################
Test: {} - {}
{}

'''

def requests_url(url):
    """ Helper function to requests WEB API GET with URL """

    resp = requests.get(url)
    if resp.status_code != 200:
        raise requests.HTTPError("GET {}".format(resp.status_code))

    return resp

def patchwork_get_series(sid):
    """ Get series detail from patchwork """

    url = PW_BASE_URL + "/series/" + sid
    req = requests_url(url)

    return req.json()

def patchwork_get_sid(pr_title):
    """
    Parse PR title prefix and get PatchWork Series ID
    PR Title Prefix = "[PW_S_ID:<series_id>] XXXXX"
    """

    try:
        sid = re.search(r'^\[PW_SID:([0-9]+)\]', pr_title).group(1)
    except AttributeError:
        logging.error("Unable to find the series_id from title %s" % pr_title)
        sid = None

    return sid

def patchwork_get_patch_detail_title(title):
    """
    Use :title to find a matching patch in series and get the detail
    """

    for patch in pw_series['patches']:
        if (patch['name'].find(title) != -1):
            logger.debug("Found matching patch title in the series")
            req = requests_url(patch['url'])
            return req.json()
        logger.debug("No matching patch title found")

    logger.error("Cannot find a matching patch from PatchWork series")

def github_pr_post_comment(name, status, output=None):
    """ Post message to PR page """

    comment = "**" + name + ": " + status + "**\n\n"
    if output:
        comment += "Output:\n"
        comment += "```\n"
        comment += output
        comment += "\n```\n"

    github_pr.create_issue_comment(comment)

def run_cmd(*args, cwd=None):
    """ Run command and return return code, stdout and stderr """

    cmd = []
    cmd.extend(args)
    cmd_str = "{}".format(" ".join(str(w) for w in cmd))
    logger.info("CMD: %s" % cmd_str)

    stdout = ""
    try:
        proc = subprocess.Popen(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                bufsize=1,
                                universal_newlines=True,
                                cwd=cwd)
    except OSError as e:
        logger.error("ERROR: failed to run cmd: %s" % e)
        return (-1, None, None)

    for line in proc.stdout:
        logger.debug(line.rstrip('\n'))
        stdout += line

    # stdout is consumed in previous line. so, communicate() returns empty
    _ignore, stderr = proc.communicate()

    logger.debug(">> STDERR\n{}".format(stderr))

    return (proc.returncode, stdout, stderr)

def config_enable(config, name):
    """
    Check "enable" in config[name].
    Return False if it is specifed otherwise True
    """

    if name in config:
        if 'enable' in config[name]:
            if config[name]['enable'] == 'no':
                logger.info("config." + name + " is disabled")
                return False

    logger.info("config." + name + " is enabled")
    return True

def send_email(sender, receiver, msg):
    """ Send email """

    email_cfg = config['email']

    if 'EMAIL_TOKEN' not in os.environ:
        logging.warning("missing EMAIL_TOKEN. Skip sending email")
        return

    try:
        session = smtplib.SMTP(email_cfg['server'], int(email_cfg['port']))
        session.ehlo()
        if 'starttls' not in email_cfg or email_cfg['starttls'] == 'yes':
            session.starttls()
        session.ehlo()
        session.login(sender, os.environ['EMAIL_TOKEN'])
        session.sendmail(sender, receiver, msg.as_string())
        logging.info("Successfully sent email")
    except Exception as e:
        logging.error("Exception: {}".format(e))
    finally:
        session.quit()

    logging.info("Sending email done")

def get_receivers(submitter):
    """
    Get list of receivers
    """

    logger.debug("Get Receivers list")
    email_cfg = config['email']

    receivers = []
    if 'only-maintainers' in email_cfg and email_cfg['only-maintainers'] == 'yes':
        # Send only to the addresses in the 'maintainers'
        maintainers = "".join(email_cfg['maintainers'].splitlines()).split(",")
        receivers.extend(maintainers)
    else:
        # Send to default-to address and submitter
        receivers.append(email_cfg['default-to'])
        receivers.append(submitter)

    return receivers

def get_sender():
    """
    Get Sender from configuration
    """
    email_cfg = config['email']
    return email_cfg['user']

def get_default_to():
    """
    Get Default address which is a mailing list address
    """
    email_cfg = config['email']
    return email_cfg['default-to']

def is_maintainer_only():
    """
    Return True if it is configured to send maintainer-only
    """
    email_cfg = config['email']

    if 'only-maintainers' in email_cfg and email_cfg['only-maintainers'] == 'yes':
        return True

    return False

def compose_email(title, body, submitter, msgid, attachments=[]):
    """
    Compose and send email
    """

    receivers = get_receivers(submitter)
    sender = get_sender()

    # Create message
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = ", ".join(receivers)
    msg['Subject'] = "RE: " + title

    # In case to use default-to address, set Reply-To to mailing list in case
    # submitter reply to the result email.
    if not is_maintainer_only():
        msg['Reply-To'] = get_default_to()

    # Message Header
    msg.add_header('In-Reply-To', msgid)
    msg.add_header('References', msgid)

    logger.debug("Message Body: %s" % body)
    msg.attach(MIMEText(body, 'plain'))

    logger.debug("Mail Message: {}".format(msg))

    # Attachment
    logger.debug("Attachment count=%d" % len(attachments))
    for logfile in attachments:
        logfile_base = os.path.basename(logfile)
        with open(logfile, "rb") as f:
            part = MIMEApplication(f.read(), Name=logfile_base)
        part['Content-Disposition'] = 'attachment; filename="%s"' % logfile_base
        msg.attach(part)
        logger.debug("Attached file: %s(%s)" % (logfile, logfile_base))

    # Send email
    send_email(sender, receivers, msg)


class Verdict(Enum):
    PENDING = 0
    PASS = 1
    FAIL = 2
    ERROR = 3
    SKIP = 4


class CiBase:
    """
    Base class for CI Tests.
    """
    name = None
    display_name = None
    enable = True

    verdict = Verdict.PENDING
    output = ""

    def success(self):
        self.verdict = Verdict.PASS

    def add_success(self, msg):
        self.verdict = Verdict.PASS
        if not self.output:
            self.output = msg
        else:
            self.output += "\n" + msg

    def error(self, msg):
        self.verdict = Verdict.ERROR
        self.output = msg
        raise EndTest

    def skip(self, msg):
        self.verdict = Verdict.SKIP
        self.output = msg
        raise EndTest

    def add_failure(self, msg):
        self.verdict = Verdict.FAIL
        if not self.output:
            self.output = msg
        else:
            self.output += "\n" + msg


class CheckPatch(CiBase):
    name = "checkpatch"
    display_name = "CheckPatch"

    checkpatch_pl = '/usr/bin/checkpatch.pl'

    def config(self):
        """
        Config the test cases.
        """
        logger.debug("Parser configuration")

        if self.name in config:
            if 'bin_path' in config[self.name]:
                self.checkpatch_pl = config[self.name]['bin_path']
        logger.debug("checkpatch_pl = %s" % self.checkpatch_pl)

    def is_workflow_patch(self, commit):
        """
        If the message contains a word "workflow", then return true.
        This is basically to prevent the workflow patch for github from running
        checkpatch and send an email to the submitter, which is nothong to do
        with the submitter
        """
        if commit.commit.message.find("workflow:") >= 0:
            return True

        return False


    def run(self):
        logger.debug("##### Run CheckPatch Test #####")

        self.enable = config_enable(config, self.name)
        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        for commit in github_commits:
            # Skip checkpatch if the patch is for workflow - workaround
            if self.is_workflow_patch(commit):
                logger.info("Skip workflow patch")
                continue

            output = self.run_checkpatch(commit.sha)
            if output != None:
                msg = "{}\n{}".format(commit.commit.message.splitlines()[0],
                                      output)
                self.add_failure(msg)

        if self.verdict != Verdict.FAIL:
            self.success()

    def run_checkpatch(self, sha):
        """
        Run checkpatch script with commit sha.
        On success, it returns None.
        On failure, it returns the stderr output string
        """

        output = None
        logger.info("Commit SHA: %s" % sha)

        diff = subprocess.Popen(('git', 'show', '--format=email', sha),
                                stdout=subprocess.PIPE,
                                cwd=src_dir)
        try:
            subprocess.check_output((self.checkpatch_pl, '--no-tree', '-'),
                                    stdin=diff.stdout,
                                    stderr=subprocess.STDOUT,
                                    shell=True,
                                    cwd=src_dir)
        except subprocess.CalledProcessError as ex:
            output = ex.output.decode("utf-8")
            logger.error("checkpatch returned error/warning")
            logger.error("output: %s" % output)

        return output


class CheckGitLint(CiBase):
    name = "checkgitlint"
    display_name = "CheckGitLint"

    gitlint_config = '/.gitlint'

    def config(self):
        """
        Config the test cases.
        """
        logger.debug("Parser configuration")

        if self.name in config:
            if 'config_path' in config[self.name]:
                self.gitlint_config = config[self.name]['config_path']
        logger.debug("gitlint_config = %s" % self.gitlint_config)

    def is_workflow_patch(self, commit):
        """
        If the message contains a word "workflow", then return true.
        This is basically to prevent the workflow patch for github from running
        checkpatch and send an email to the submitter, which is nothong to do
        with the submitter
        """
        if commit.commit.message.find("workflow:") >= 0:
            return True

        return False

    def run(self):
        logger.debug("##### Run CheckGitLint Test #####")

        self.enable = config_enable(config, self.name)
        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        for commit in github_commits:
            # Skip checkpatch if the patch is for workflow - workaround
            if self.is_workflow_patch(commit):
                logger.info("Skip workflow patch")
                continue

            output = self.run_checkgitlint(commit.sha)
            if output != None:
                msg = "{}\n{}".format(commit.commit.message.splitlines()[0],
                                      output)
                self.add_failure(msg)

        if self.verdict != Verdict.FAIL:
            self.success()

    def run_checkgitlint(self, sha):
        """
        Run checkpatch script with commit sha.
        On success, it returns None.
        On failure, it returns the stderr output string
        """

        output = None
        logger.info("Commit SHA: %s" % sha)

        commit = subprocess.Popen(('git', 'log', '-1', '--pretty=%B', sha),
                                  stdout=subprocess.PIPE,
                                  cwd=src_dir)
        try:
            subprocess.check_output(('gitlint', '-C', self.gitlint_config),
                                    stdin=commit.stdout,
                                    stderr=subprocess.STDOUT,
                                    shell=True,
                                    cwd=src_dir)
        except subprocess.CalledProcessError as ex:
            output = ex.output.decode("utf-8")
            logger.error("gitlint returned error/warning")
            logger.error("output: %s" % output)

        return output


class CheckBuildK(CiBase):
    name = "checkbuildk"
    display_name = "CheckBuildK"

    build_config = "/bluetooth_build.config"

    def config(self):
        """
        Configure the test cases.
        """
        logger.debug("Parser configuration")

        if self.name in config:
            if 'config_path' in config[self.name]:
                self.build_config = config[self.name]['config_path']
        logger.debug("build_config = %s" % self.build_config)

    def run(self):
        logger.debug("##### Run CheckBuildK Test #####")

        self.enable = config_enable(config, self.name)

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        # Copy bluetooth build config
        logger.info("Copy config file: %s" % self.build_config)
        (ret, stdout, stderr) = run_cmd("cp", self.build_config, ".config",
                                        cwd=src_dir)
        if ret:
            self.add_failure(stderr)
            raise EndTest

        # Update .config
        logger.info("Run make olddepconfig")
        (ret, stdout, stderr) = run_cmd("make", "olddefconfig", cwd=src_dir)
        if ret:
            self.add_failure(stderr)
            raise EndTest

        # make
        (ret, stdout, stderr) = run_cmd("make", cwd=src_dir)
        if ret:
            self.add_failure(stderr)
            raise EndTest

        # At this point, consider test passed here
        self.success()


class CheckTestRunnerSetup(CiBase):
    name = "checktestrunnersetup"
    display_name = "CheckTestRunner: Setup"

    test_list = []
    runner = None
    kernel_img = None
    result_logs = []

    def config(self):
        """
        Configure the test cases.
        """
        logger.debug("Parser configuration")

        default_test_list = ["bnep-tester",
                             "l2cap-tester",
                             "mgmt-tester",
                             "rfcomm-tester",
                             "sco-tester",
                             "smp-tester",
                             "userchan-tester"]

        if self.name in config:
            if 'test_list' in config[self.name]:
                self.test_list = "".join(config[self.name]['test_list'].splitlines()).split(",")
            else:
                self.test_list = default_test_list
        logger.debug("test list = %s" % self.test_list)

    def build_bluez(self):
        """
        Build BlueZ and return the path of test-runner otherwiase None
        """
        logger.debug("Build BlueZ Source")

        # Configure BlueZ
        logger.info("Configure the BlueZ source")
        (ret, stdout, stderr) = run_cmd("./bootstrap-configure",
                                        "--enable-external-ell",
                                        cwd=bluez_dir)
        if ret:
            logger.error("Unable to configure the bluez")
            return None

        # make
        logger.info("Run make")
        (ret, stdout, stderr) = run_cmd("make", "-j2", cwd=bluez_dir)
        if ret:
            logger.error("Unable to build bluez")
            return None

        tester_path = os.path.join(bluez_dir, "tools/test-runner")
        if not os.path.exists(tester_path):
            logger.error("Unable to find the test-runner binary")
            return None

        logger.debug("test-runner path: %s" % tester_path)
        return tester_path

    def build_kernel(self):
        """
        Build Bluetooth-Next with tester.config and return the path of
        kernel image file otherwise None
        """
        logger.debug("Build Bluetooth-Next Source with tester config")

        # Default tester config
        # TODO: Pick up from the BlueZ Source doc/tester.config
        build_config = "/tester.config"

        # Copy bluetooth build config
        logger.info("Copy tester config file: %s" % build_config)
        (ret, stdout, stderr) = run_cmd("cp", build_config, ".config",
                                        cwd=src_dir)
        if ret:
            logger.error("Unable to copy config file")
            return None

        # Update .config
        logger.info("Run make olddefconfig")
        (ret, stdout, stderr) = run_cmd("make", "olddefconfig", cwd=src_dir)
        if ret:
            logger.error("Unable to run make olddefconfig")
            return None

        # make
        (ret, stdout, stderr) = run_cmd("make", "-j2", cwd=src_dir)
        if ret:
            logger.error("Unable to make the image")
            return None

        # Retrun image file
        bzimage_path = os.path.join(src_dir, "arch/x86/boot/bzImage")
        if not os.path.exists(bzimage_path):
            logger.error("Unable to find bzImage from: %s" % bzimage_path)
            return None

        logger.debug("bzImage file from: %s" % bzimage_path)
        return bzimage_path

    def run(self):
        logger.debug("##### Run CheckTestRunner Setup #####")

        global test_runner_context

        self.enable = config_enable(config, self.name)

        self.config()

        # Check if it is disabled.
        if self.enable == False:
            self.skip("Disabled in configuration")

        # Build BlueZ
        self.runner = self.build_bluez()
        if self.runner == None:
            self.add_failure("Unable to build BlueZ source")
            raise EndTest

        # Build Kernel image for tester
        self.kernel_img = self.build_kernel()
        if self.kernel_img == None:
            self.add_failure("Unable to build Kernel image for tester")
            raise EndTest

        # At this point, consider test passed here
        test_runner_context = self
        self.success()


class CheckTestRunner(CiBase):
    name = "checktestrunner"
    display_name = "CheckTestRunner: "
    tester = None
    test_summary = None

    def __init__(self, tester="default"):
        """
        Init test object for tester
        """
        self.tester = tester
        self.name = self.name + tester
        self.display_name = self.display_name + tester

    def config(self):
        """
        Configure the test cases.
        """
        logger.debug("Parser configuration - nothing to do. skip")

    def save_result_log(self, log):
        """
        Save the test result(log) to the file
        """

        logfile_path = os.path.join(output_dir, self.tester + ".log")
        logger.debug("Save the result to the file: %s" % logfile_path)
        with open(logfile_path, 'w') as output_file:
            output_file.write(log)

        # Save the logfile path to the context for later use (attachment)
        test_runner_context.result_logs.append(logfile_path)

    def parse_result(self, results):
        """
        Parse the result line generated by the tester and returns the dict
        with total, passed, failed, not run, otherwise None.
        """

        regex = r"^Total:\s+(?P<total>\d+)\,\s+Passed:\s+(?P<passed>\d+)\s+\(.+\%\)\,\s+Failed:\s+(?P<failed>\d+)\,\s+Not\s+Run:\s+(?P<notrun>\d+)"
        matches = re.search(regex, results)
        if not matches:
            logger.error("Unable to parse the result line: %s" % results)
            return None

        logger.debug(matches.groupdict().items())
        return matches.groupdict()

    def run(self):
        logger.debug("##### Run CheckTestRunner - %s #####" % self.tester)

        self.config()

        # Check if testrunner is ready
        if test_runner_context == None:
            logger.debug("Test Runner is Not Ready. Skip testing %s" % self.tester)
            self.skip("Test Runner is Not Ready")

        # Get Tester Path
        tester_path = os.path.join(bluez_dir, "tools", self.tester)
        if not os.path.exists(tester_path):
            self.add_failure("Unable to find tester: %s" % tester_path)
            raise EndTest

        # Running Tester
        (ret, stdout, stderr) = run_cmd(test_runner_context.runner, "-k", test_runner_context.kernel_img, "--", tester_path)
        if ret:
            logger.error("Failed to run tester: ret: %d" % ret)
            self.add_failure("Failed to run tester")
            raise EndTest

        # Remove terminal color macro
        stdout_clean = re.sub(r"\x1B\[\d?\;?\d+m", "", stdout)

        # Save the result to the log file
        self.save_result_log(stdout_clean)

        check_fail = False
        failed_tc = []

        # verdict result
        for line in stdout_clean.splitlines():
            if re.search(r"^Total: ", line):
                self.test_summary = line

                result = self.parse_result(line)
                if result["failed"] != "0":
                    logger.error("Some test failed - Return failure")
                    self.add_failure(line)

                    # Adding Failed test cases
                    if len(failed_tc):
                        self.add_failure("\nFailed Test Cases")
                        for tc in failed_tc:
                            self.add_failure(tc)

                    # No need to check failure
                    check_fail = False
                    return

                self.add_success(line)
                return

            if re.search(r"^Test Summary", line):
                logger.debug("Start to check failure in the line")
                check_fail = True

            if check_fail and re.search(r"Failed", line):
                logger.debug("Found a failed test case")
                failed_tc.append(line)

        self.add_failure("No test result found")


class EndTest(Exception):
    """
    End of Test
    """


def run_ci(args):
    """
    Run CI tests and returns the number of failed tests
    """

    global test_suite

    num_fails = 0

    if args.show_test_list:
        for testcase in CiBase.__subclasses__():
            print(testcase.name)
        return 0

    # Run tests
    for testcase in CiBase.__subclasses__():

        # skip for test runner class
        if testcase.__name__ == "CheckTestRunner":
            logger.debug("Skip for test runner class for now")
            break

        test = testcase()

        test_suite[test.name] = test

        try:
            test.run()
        except EndTest:
            logger.debug("Test Ended")

        logger.info("Process test result for " + test.name)

        if test.verdict == Verdict.FAIL:
            num_fails += 1

        logger.info(test.name + " result: " + test.verdict.name)
        logger.debug("Post message to github: " + test.output)
        github_pr_post_comment(test.name, test.verdict.name, test.output)

    if test_runner_context:
        logger.debug("Running for tester")
        for tester in test_runner_context.test_list:
            logger.debug("running tester: %s" % tester)
            test = CheckTestRunner(tester)
            test_suite[test.name] = test

            try:
                test.run()
            except EndTest:
                logger.debug("Test Ended")

            logger.info("Process test result for " + test.name)

            if test.verdict == Verdict.FAIL:
                num_fails += 1

            logger.info(test.name + " result: " + test.verdict.name)
            logger.debug("Post message to github: " + test.output)
            github_pr_post_comment(test.name, test.verdict.name, test.output)

    return num_fails

def report_ci():
    """
    Generate CI result report and send email
    """


    results = ""

    for test_name, test in test_suite.items():
        if test.verdict == Verdict.PASS:
            results += TEST_REPORT.format(test.display_name, "PASS", test.output)
        if test.verdict == Verdict.FAIL:
            results += TEST_REPORT.format(test.display_name, "FAIL", test.output)
        if test.verdict == Verdict.ERROR:
            results += TEST_REPORT.format(test.display_name, "ERROR", test.output)
        if test.verdict == Verdict.SKIP:
            results += TEST_REPORT.format(test.display_name, "SKIPPED", test.output)

    body = EMAIL_MESSAGE.format(pw_series["web_url"], results)

    patch = pw_series['patches'][0]

    # Compose email and send
    compose_email(pw_series['name'], body, pw_series['submitter']['email'], patch['msgid'],
                  test_runner_context.result_logs)

def init_github(repo, pr_num):
    """
    Initialize github object
    """

    global github_repo
    global github_pr
    global github_commits
    global pw_sid
    global pw_series

    github_repo = Github(os.environ['GITHUB_TOKEN']).get_repo(repo)
    github_pr = github_repo.get_pull(pr_num)
    github_commits = github_pr.get_commits()

    pw_sid = patchwork_get_sid(github_pr.title)
    pw_series = patchwork_get_series(pw_sid)

def init_logging(verbose):
    """
    Initialize the logger and default level is INFO or DEBUG if @verbose
    is True
    """

    global logger

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    if verbose:
        logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s:%(levelname)-8s:%(message)s')
    ch.setFormatter(formatter)

    logger.addHandler(ch)

    logger.info("Logger is initialized: level=%s",
                 logging.getLevelName(logger.getEffectiveLevel()))

def init_config(config_file, verbose=False):
    """
    Read @config_file and initialize the values if necessary
    """

    global config

    config = configparser.ConfigParser()

    config_full_path = os.path.abspath(config_file)
    if not os.path.exists(config_full_path):
        raise FileNotFoundError

    logger.info("Loading config file: %s" % config_full_path)
    config.read(config_full_path)

    # Display current config settings
    if verbose == True:
        for section in config.sections():
            logger.debug("[%s]" % section)
            for (key, val) in config.items(section):
                logger.debug("   %s : %s" % (key, val))

def parse_args():

    parser = argparse.ArgumentParser(
        description="Check patch style in the pull request")
    parser.add_argument('-c', '--config-file', default='config.ini',
                        help='Configuration file')
    parser.add_argument('-l', '--show-test-list', action='store_true',
                        help='Display supported CI tests')
    parser.add_argument('-p', '--pr-num', required=True, type=int,
                        help='Pull request number')
    parser.add_argument('-r', '--repo', required=True,
                        help='Github repo in :owner/:repo')
    parser.add_argument('-s', '--src-path', required=True,
                        help='Path of bluetooth kernel source')
    parser.add_argument('-b', '--bluez-path', required=True,
                        help='Path of bluez source')
    parser.add_argument('-o', '--output-path', required=True,
                        help='Path for tester outputs')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Display debugging info')

    return parser.parse_args()

def main():

    global src_dir, bluez_dir, output_dir

    args = parse_args()

    init_logging(args.verbose)

    init_config(args.config_file, args.verbose)

    init_github(args.repo, args.pr_num)

    src_dir = args.src_path
    bluez_dir = args.bluez_path
    output_dir = os.path.abspath(args.output_path)
    if not os.path.exists(output_dir):
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        logger.debug("Created outputdirectory: %s" % output_dir)

    logger.debug("Fetch commits in the tree: %d commits" % github_pr.commits)
    pr_commits = github_pr.commits
    logger.debug("Expand the commits in PR to the src: %d" % pr_commits)
    (ret, stdout, stderr) = run_cmd("git", "fetch", "--depth=%d" % pr_commits,
                                    cwd=src_dir)
    if ret:
        logger.error("Failed to fetch the PR commits. error=%s" % stderr)
    else:
        logger.debug("output>>\n%s" % stdout)

    # Run CI tests
    try:
        num_fails = run_ci(args)
    except BaseException:

        # Just for debugging purpose, post the result to the github comments
        # TODO: github_commnet()
        raise

    # Generate email and report
    report_ci()

    sys.exit(num_fails)

if __name__ == "__main__":
    main()
