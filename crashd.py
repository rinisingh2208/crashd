################################################
import subprocess
import re
import sys
import socket
import os
sys.path.append('../')
from vault import vault as vault
import paramiko
import logging
import tarfile
import warnings
from datetime import datetime
from cryptography.utils import CryptographyDeprecationWarning

path = os.path.dirname(os.path.abspath(__file__))+'/'

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("debug.log"),
        logging.StreamHandler()
    ]
)
logging.info("pwd : "+ path)
time = datetime.now().strftime('%Y-%m-%d-%H:%M:%S.%f')
logging.info("Creating directory to store result based on timestamp")
extracting_crashd = subprocess.Popen(
    ["mkdir", path+"report_" + time],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE)
output, errors = extracting_crashd.communicate()
extracting_crashd.wait()
logging.debug(output)
logging.error(errors)

# logging.info("Installing crashd binary")
# installing_crashd = subprocess.Popen(["wget",
#                                      "https://github.com/vmware-tanzu/crash-diagnostics/releases/download/v0.3.7/crashd_0.3.7_linux_amd64.tar.gz"],
#                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
# output, errors = installing_crashd.communicate()
# installing_crashd.wait()
# print(output)
# print(errors)

def check_ssh(ip, port=22):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, int(port)))
        s.shutdown(2)
        return True
    except:
        return False

logging.info("Removing crashd binary from /usr/local/bin")
moving_crashd = subprocess.Popen(["sudo", "rm", "-rf", "/usr/local/bin/crashd"], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
output, errors = moving_crashd.communicate()
moving_crashd.wait()
logging.debug(output)
logging.error(errors)

logging.info("Extracting crashd binary")
extracting_crashd = subprocess.Popen(["tar", "-xf", path+"crashd_0.3.7_linux_amd64.tar.gz"],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
output, errors = extracting_crashd.communicate()
extracting_crashd.wait()
logging.debug(output)
logging.error(errors)

logging.info("Copying crashd binary to executable part")
moving_crashd = subprocess.Popen(["sudo", "cp", path+"crashd", "/usr/local/bin"], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
output, errors = moving_crashd.communicate()
moving_crashd.wait()
logging.debug(output)
logging.error(errors)

logging.info("Fecthing master ips")
print_master_ips = subprocess.Popen(
    ["kubectl", "get", "nodes", "-o", "wide", "-l", "node-role.kubernetes.io/master", "-o",
     "jsonpath={.items[*].status.addresses[*].address}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
output, errors = print_master_ips.communicate()

ips = str(output).split(" ")
ips=[x.lstrip("b").lstrip("'") for x in ips ]
master_ip_tmp = []
master_ip = []
pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
master_ip_tmp = list(filter(pattern.match, ips))
for ip in master_ip_tmp:
    status = check_ssh(ip)
    if status == True:
        master_ip.append(ip)
    else:
        pass
# displaying the extracted IP addresses
print(str(master_ip) + "\n")

logging.info("Fetching all IPS")
print_complete_ips = subprocess.Popen(
    ["kubectl", "get", "nodes", "-o", "wide", "-o", "jsonpath={.items[*].status.addresses[*].address}"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE)

output, errors = print_complete_ips.communicate()

ips = str(output).split(" ")

complete_ip_tmp = []
complete_ip = []
pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
complete_ip_tmp = list(filter(pattern.match, ips))
for ip in complete_ip_tmp:
    status = check_ssh(ip)
    if status == True:
        complete_ip.append(ip)
    else:
        pass

# displaying the extracted IP addresses
print(str(complete_ip) + "\n")

worker_ips_set = set(complete_ip) - set(master_ip)
worker_ips = list(worker_ips_set)

result_files = []
for ip in master_ip:
    cmd = "crashd run --args=\"master_ip={0}, path={1}\" " "{1}diagnostic.crsh" .format(ip,path)
    logging.info("Running diagnostic script on master for " + ip)
    print(cmd)
    run_crashd_script = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, errors = run_crashd_script.communicate()
    run_crashd_script.wait()
    logging.debug(output)
    logging.error(errors)
    cmd = ["mv", "diagnostics" + ip + ".tar.gz",
           path+"report_" + time + "/diagnostics" + ip + ".tar.gz"]
    result_files.append(
        path+"report_" + time + "/diagnostics" + ip + ".tar.gz")
    # print(cmd)
    run_mv_result = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, errors = run_mv_result.communicate()
    run_mv_result.wait()
    logging.debug(output)
    logging.error(errors)


def install_and_import(package):
    import importlib
    try:
        importlib.import_module(package)
    except ImportError:
        if sys.version_info[0] < 3:
           installing_pip = subprocess.Popen(["sudo", "pip", "install", path+"scp-0.14.4-py2.py3-none-any.whl"], stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE)
        else:
             installing_pip = subprocess.Popen(["sudo", "pip3", "install", path+"scp-0.14.4-py2.py3-none-any.whl"], stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE)
        output, errors = installing_pip.communicate()
        moving_crashd.wait()
        logging.debug(output)
        logging.error(errors)

    finally:
        globals()[package] = importlib.import_module(package)


class remoExec(object):
    def __init__(self):
        self.sshuser = vault.yFetch("node", "username", "")
        self.sshpassword = vault.yFetch("node", "password", "")

    def exec_copy_script(self, ip, script):
        # connect to server
        con = paramiko.SSHClient()
        con.load_system_host_keys()
        con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        con.connect(ip, username=self.sshuser, password=self.sshpassword)

        # copy the file across
        from scp import SCPClient, SCPException
        with SCPClient(con.get_transport()) as scp:
            logging.info("Copying diagnostic script " + ip)
            scp.put(script, '/tmp')

    def exec_copy_log(self, ip):
        # connect to server
        con = paramiko.SSHClient()
        con.load_system_host_keys()
        con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        con.connect(ip, username=self.sshuser, password=self.sshpassword)

        # copy the logs
        from scp import SCPClient, SCPException
        logging.info("Copying result from " + ip)
        with SCPClient(con.get_transport()) as scp:
            scp.get('/home/centos/diagnostics' + ip + '.tar.gz', '/home/centos/diagnostics' + ip + '.tar.gz')
        moving_output = subprocess.Popen(["sudo", "mv", '/home/centos/diagnostics' + ip + '.tar.gz',
                                          path+"report_" + time],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, errors = moving_output.communicate()
        moving_output.wait()
        logging.debug(output)
        logging.error(errors)

    def exec_script(self, ip):
        # connect to server
        con = paramiko.SSHClient()
        con.load_system_host_keys()
        con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        con.connect(ip, username=self.sshuser, password=self.sshpassword)
        from scp import SCPClient, SCPException
        with SCPClient(con.get_transport()) as scp:
            try:
                if os.path.isfile(path+'crashd'):
                    scp.put(path+'crashd', '/tmp')
                else:
                    if os.path.isfile('/usr/local/bin/crashd'):
                        scp.put('/usr/local/bin/crashd', '/tmp')
                    else:
                        print("Trouble copying binary file crashd to worker node " + ip)
            except Exception as e:
                print(e)

        # install crashd
        # logging.info("Installing crashd binary on " + ip)
        # cmd = "wget https://github.com/vmware-tanzu/crash-diagnostics/releases/download/v0.3.7/crashd_0.3.7_linux_amd64.tar.gz"
        # stdin, stdout, stderr = con.exec_command(cmd)
        # print(stdout.read().decode())
        # logging.debug(stdout.read().decode())
        # logging.error(stderr.read())

        cmd2 = "sudo -S mv  /tmp/crashd /usr/local/bin"
        stdin, stdout, stderr = con.exec_command(cmd2)
        stdin.write(self.sshpassword + "\n")
        stdin.flush()
        logging.debug(stdout.read().decode())
        logging.error(stderr.read())

        # execute the script
        global result_files
        logging.info("Running diagnostic script on worker for " + ip)
        result_files.append(
            path+"report_" + time + "/diagnostics" + ip + ".tar.gz")
        cmd = "crashd run --args=\"master_ip=%s, path=%s\" " "/tmp/diagnostic.crsh" % (ip,path)
        print(cmd)
        logging.info("run commands : {0}".format(str(cmd)))
        stdin, stdout, stderr = con.exec_command(cmd)
        logging.debug(stdout.read().decode())
        logging.error(stderr.read().decode())
        return result_files

    def exec_pass_script(self, ip):
        # connect to server
        con = paramiko.SSHClient()
        con.load_system_host_keys()
        con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        con.connect(ip, username=self.sshuser, password=self.sshpassword)
        logging.info("Setting passwordless setting for diagnostic script to run on " + ip)
        cmd = "python /tmp/ssh_passwordless_setup.py " + ip + " -U " + self.sshuser + " -P " + self.sshpassword
        # print(cmd)
        # logging.info("run commands : {0}".format(str(cmd)))
        stdin, stdout, stderr = con.exec_command(cmd)
        print(stdout.read().decode())
        logging.debug(stdout.read().decode())
        logging.error(stderr.read().decode())

    def exec_sudoers(self, ip):
        # connect to server
        con = paramiko.SSHClient()
        con.load_system_host_keys()
        con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        con.connect(ip, username=self.sshuser, password=self.sshpassword)
        cmd = """ echo "centos ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers"""
        stdin, stdout, stderr = con.exec_command(cmd, get_pty=True)
        stdin.write(self.sshpassword + '\n')
        stdin.flush()
        # print(stdout.read().decode())
        logging.debug(stdout.read().decode())
        logging.error(stderr.read().decode())


install_and_import("scp")
remote_object = remoExec()
for worker_ip in worker_ips:
    # remote_object.exec_script(worker_ip)
    remote_object.exec_copy_script(worker_ip, path+'diagnostic.crsh')
    remote_object.exec_copy_script(worker_ip, path+'ssh_passwordless_setup.py')
    remote_object.exec_pass_script(worker_ip)
    remote_object.exec_sudoers(worker_ip)
    result_files = remote_object.exec_script(worker_ip)
    remote_object.exec_copy_log(worker_ip)

logging.info("Started to extractall")
for i in result_files:
    with tarfile.open(i) as tar:
        tar.extractall(path='.')

# removing file with NotFound Message
logging.info("Started to remove NotFound & refused and Empty files")
cmd_Del = """grep -l -R --include=* NotFound ./ --exclude="*.py" --exclude="*.tar.gz" --exclude="*log_deployment_sh.txt"|xargs rm"""
deleting_files = subprocess.Popen(cmd_Del, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, shell=True)
output, errors = deleting_files.communicate()
deleting_files.wait()
logging.debug(output)
logging.error(errors)

# removing file with refused Message
cmd_Del2 = """grep -l -R --include="*" "The connection to the server localhost:8080 was refused - did you specify the right host or port?" ./ --exclude="*.py" --exclude="*.tar.gz" --exclude="*log_deployment_sh.txt"| xargs rm"""
deleting_files2 = subprocess.Popen(cmd_Del2, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=True)
output, errors = deleting_files2.communicate()
deleting_files2.wait()
logging.debug(output)
logging.error(errors)

# removing empty file
cmd_Del3 = """find . -type f \( -name "*.txt" \) -empty -print -delete"""
deleting_files3 = subprocess.Popen(cmd_Del3, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=True)
output, errors = deleting_files3.communicate()
deleting_files3.wait()
logging.debug(output)
logging.error(errors)

logging.info("Started to archive")
archive_name = path+"report_" + time + "/result"
files2 = master_ip + worker_ips
try:
    with tarfile.open(archive_name + '.tar.gz', mode='w:gz') as archive:
        for i in files2:
            archive.add(i, recursive=True)
except:
    pass

logging.info("Started to remove folders with IP")
for ip in complete_ip:
    cmd = ["rm", "-rf", path + ip]
    rm_files = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, errors = rm_files.communicate()
    rm_files.wait()
    logging.debug(output)
    logging.error(errors)

logging.info("Running analyze script")
cmd = "crashd run --args=\"master_ip={0}, path={1}\" " "{1}analyze.crsh" .format(master_ip[0],path)
print(cmd)
run_crashd_script = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
output, errors = run_crashd_script.communicate()
run_crashd_script.wait()
logging.info(output)
logging.error(errors)

print("Result stored in "+path+"report_" + time + "/result.tar.gz")
