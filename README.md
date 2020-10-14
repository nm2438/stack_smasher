# stack_smasher
A tool for conducting local and remote/socket-based buffer overflows.
Tools for bypassing certain types of stack protection to be featured in a future release

README last updated on: 14OCT2020

Feel free to report bugs via Issues or request to collaborate

### Usage
For now, it is a purely interactive script. Run 

> ./stack_smasher.py

or

> python3 ./stack_smasher.py

and follow the menus

Argparsing/command line switches coming soon

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
  <ul>
    <li>At time of writing, changing settings is not supported, but feature should be added by end of day</li>
  </ul>
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
    <li>Determine buffer size/EIP offset automatically</li>
    <ul>
      <li>Requires access to dmesg</li>
      <li>Values can also be entered manually</li>
    </ul>
    <li>Add any additional target EIPs</li>
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
  <li><del>Easily change exploit settings</del></li>
  <li><del>Command line switches, Usage statement, and Help statement (all via Argparse library)</del></li>
  <li>Automatic local Windows exploits (to mirror the local linux capabilities)</li>
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
