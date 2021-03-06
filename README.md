# stack_smasher
A tool for conducting local and remote/socket-based buffer overflows.
Tools for bypassing certain types of stack protection to be featured in a future release

README last updated on: 16OCT2020

Feel free to report bugs via Issues or request to collaborate

### Usage

```
usage: stack_smasher.py [-h] [-i] [-l LOAD] [-m]

A tool for conducting local and remote/socket-based buffer overflows.     

optional arguments:
  -h, --help            show this help message and exit
  -i, --interactive     open script in interactive mode
  -l LOAD, --load LOAD  load: specify a file from which to load an exploit
  -m, --manual          jump to manual message writer mode
```

## So, what's it good for?

#### From the Main Menu, you can:
<ul>
  <li>Create a new exploit</li>
  <ul>
    <li>(More on exploit functionality later)</li>
  </ul>
  <li>Load an exploit from a settings file</li>
  <li>Switch between currently loaded exploits</li>
  <ul>
    <li>Let's say you create an exploit, return to the main menu, then load an old exploit. You can still retrieve the exploit you created before exiting the script by switching between the loaded exploits</li>
  </ul>
  <li>Exit the script</li>
  <ul>
    <li>Or, you know, Ctrl+C like a normal person</li>
  </ul>
</ul>
  
#### From the Exploit Menu, you can:
<ul>
  <li>View the current exploit's settings</li>
  <li>Change the current exploit's settings</li>
  <li>Save the current exploit settings to a file (to be loaded back into the script at a later day or time)</li>
  <li>Run the exploit</li>
  <ul>
    <li>Send the payload to the local/remote application</li>
  </ul>
  <li>Exit the exploit handler/Return to the main menu</li>
</ul>      

#### Exploit Functionality:
##### Currently Supported Exploit Types and Functionalities for Each
<ul>
  <li><strong>Local Linux</strong> (Target binary/executable is on the local system, and the local OS is some variety of Linux)</li>
  <ul>
    <li><strong>NEW:</strong> Supports sending payload via stdin OR via cmdline argument</li>
    <li>Determine buffer size/EIP offset automatically</li>
    <ul>
      <li>Requires access to dmesg</li>
      <li>Values can also be entered manually</li>
    </ul>
    <li>Add any additional target EIPs</li>
    <li>Manually enter any commands and/or cmdline arguments needed to trigger the overflow vulnerability</li>
    <li>Specify number of NOPs to prepend/append to the shellcode</li>
    <li>Set shellcode</li>
    <ul>
      <li>Can generate an msfvenom payload without leaving the script -- if you have access to msfvenom on the local host</li>
      <li>Otherwise, you can:</li>
      <ul>
        <li>Use one of the preset payloads built into the script</li>
        <li>Enter your shellcode manually as a string</li>
      </ul>
    </ul>
    <li>Run the exploit</li>
    <ul>
      <li>You can specify a buffer size confidence interval to try multiple buffer sizes</li>
      <li>You can specify an EIP confidence interval to try multiple EIPs (centered around each of the target EIPs already specified)</li>
      <ul>
        <li>Interval goes forward/back in byte increments</li>
        <li><strong>NOTE:</strong> Extremely large EIP intervals are recommended for executables that accept payload via cmdline args (based on preliminary testing)</li>
      </ul>
    </ul>
  </ul>
  <li><strong>Remote</strong> (Any target OS)</li>
  <ul>
    <li>Manually enter buffer size and as many target EIPs as you'd like</li>
    <li>Manually enter any commands needed to trigger the overflow vulnerability</li>
    <li>Specify number of NOPs to prepend/append to the shellcode</li>
    <li>Set shellcode</li>
    <ul>
      <li>Can generate an msfvenom payload without leaving the script -- if you have access to msfvenom on the local host</li>
      <li>Otherwise, you can:</li>
      <ul>
        <li>Use one of the preset payloads built into the script (one for linux, one for windows)</li>
        <li>Enter your shellcode manually as a string</li>
      </ul>
    </ul>
    <li>Run the exploit</li>
    <ul>
      <li>You can specify a buffer size confidence interval to try multiple buffer sizes</li>
      <li>You can specify an EIP confidence interval to try multiple EIPs (centered around each of the target EIPs already specified)</li>
      <ul>
        <li>Interval goes forward/back in byte increments</li>
      </ul>
    </ul>
  </ul>
</ul>
  
    
## Future Releases
<ul>
  <li><del>Easily change exploit settings</del> Done</li>
  <li><del>Command line switches, Usage statement, and Help statement (all via Argparse library)</del> Done</li>
  <li><del>Bug Fixes</del> Done</li>
    <ul>
      <li><del>"Zero" option for confidence intervals</del> Done</li>
      <li><del>Correctly read in EIP lists with only a single item</del> Done</li>
      <li><del>Reset menu choice after returning from subfunctions</del> Done</li>
      <li><del>Hang for ENTER after printing "Missing" in self.run()</del> Done</li>
      <li><del>Change "if not []"'s to "if []==None"</del> Done</li>
      <li><del>Change get_buffer_size overflow verification to be more reliable</del> Done</li>
      <li><del>Fix msfvenom integration</del> Done</li>
      <li><del>Always generate payload before saving file</del> Done</li>
    </ul>
  <li><del>Additional linux built-in shellcodes</del> Done</li>
  <li><del>Local linux exploits that accept payload as argument rather than stdin</del></li>
    <ul>
      <li><del>Successfully tested?</del> Yes!</li>
      <li><del>Update README</del></li>
    </ul>
  <li><del>Manual hex message writer</del></li>
  <li>Add ability to print payload to stdout or to file in a variety of different formats</li>
  <li>Automatic local Windows exploits (to mirror the local linux capabilities)</li>
  <li>Return to "set shellcode" menu from "change settings" menu</li>
  <li>Analysis module to automatically perform basic remote exploits, as long as a copy of the target application is available locally</li>
  <li>Additional payload generation methods to overcome basic stack protection/stack canaries</li>
  <ul>
    <li>Static Canaries (usually only seen in contrived examples)</li>
    <li>Canary Leak (requires a loop with a fork in the source code as opposed to an execve)</li>
    <ul>
      <li>A forked child process retains the parent's canary, which does not change until the parent process is restarted. An execve child process will obtain its own unique stack canary value</li>
    </ul>
    <li>Byte-by-byte Canary Brute-Force (Requires a loop with a fork in the source code as opposed to an execve)</li>
  </ul>
</ul>
  
 </ul>
