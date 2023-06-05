from datetime import datetime

import paramiko
from paramiko import AuthenticationException, SSHException


class SSHClient:
    def __init__(
        self,
        ip,
        user,
        ssh_key=None,
        key_password=None,
        password=None,
        log_file="exe.log",
    ):
        self.ip = ip
        self.user = user
        self.ssh_key = self._ssh_key(ssh_key, key_password)
        self.password = password
        self.log_file = log_file

        self.client = paramiko.SSHClient()

        self._connect()
        return

    def cmd(self, command, sudo=False, sudo_password=None):
        if sudo and sudo_password is not None:
            command = command.replace("'", "'\\''")
            full_command = f"echo {sudo_password} | sudo -S bash -c '{command}'"
        else:
            full_command = command
            pass
        _, stdout, stderr = self.client.exec_command(full_command)
        stdout = stdout.read().decode()
        stderr = stderr.read().decode()
        self._log(full_command, stdout, stderr)
        return stdout, stderr

    def __del__(self):
        self._disconnect()
        return

    def _log(self, full_command, stdout, stderr):
        with open(self.log_file, "a") as f:
            tmp1 = "[{}]: ssh command host=[{}] user=[{}]\n".format(
                datetime.now(), self.ip, self.user
            )
            stdout_ = stdout.replace("\n", "\n    ")
            stderr_ = stderr.replace("\n", "\n    ")
            tmp2 = "  input:\n    {}\n  ".format(full_command)
            tmp3 = "stdout:\n    {}\n  stderr:\n    {}".format(stdout_, stderr_)
            print(
                "{}{}{}".format(tmp1, tmp2, tmp3),
                file=f,
            )
            pass
        return

    def _ssh_key(self, ssh_key, key_password):
        if ssh_key is None:
            return None

        if "rsa" in ssh_key:
            return paramiko.RSAKey.from_private_key_file(ssh_key, password=key_password)
        elif "ed25519" in ssh_key:
            return paramiko.Ed25519Key.from_private_key_file(
                ssh_key, password=key_password
            )

        return None

    def _connect(self):
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if self.ssh_key:
                self.client.connect(self.ip, username=self.user, pkey=self.ssh_key)
            else:
                self.client.connect(self.ip, username=self.user, password=self.password)
                pass
        except (AuthenticationException, SSHException) as error:
            print(f"Failed to connect: {error}")
            pass
        return

    def _disconnect(self):
        self.client.close()
        return

    pass


if __name__ == "__main__":
    client = SSHClient("localhost", "", ssh_key="")
    cmd = "echo 'hello' && echo \"world\""
    stdout, stderr = client.cmd(cmd, sudo=True, sudo_password="")
    print("stdout")
    print(stdout)
    print("\nstderr")
    print(stderr)
