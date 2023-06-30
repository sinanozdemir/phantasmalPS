# phantasmalPS
This Python script generates a PowerShell Process Injection script with AES encrypted shellcode.

Install requirements:
```python
pip3 install -r requirements.txt
```

Simple Usage:
```bash
python3 phantasmalPS.py -h
```
![Help](Images/phantasmalPS-help.png)

```bash
python3 effectiveShellShocker.py test http://172.16.80.22 /cgi-bin /calendar.cgi
```
![Test](Images/test.png)

```bash
python3 effectiveShellShocker.py attack http://172.16.80.22 /cgi-bin /calendar.cgi
```
![Attack](Images/attack.png)

Reverse shell:

![Reverse Shell](Images/reverseshell.png)

Thank you
