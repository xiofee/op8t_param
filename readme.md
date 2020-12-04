# OnePlus 8T Param Partition Tool

Read/Write OnePlus 8T Param Partition Params.

For example, OnePlus 8T read param id 4 param to identify Cyberpunk edition.

You can change param id 4 to 8 to enable Cyberpunk edition theme.

## Requirements

- python 3
- pycryptodome

## Usage

```
usage: op8t_param.py [-h] {list,read,write} ...

OnePlus 8T param tools

positional arguments:
  {list,read,write}
    list             list available ids
    read             read
    write            write

optional arguments:
  -h, --help         show this help message and exit
```

### List Knowed ID

```
➜  python op8t_param.py list

id: 1 desc: Intranet
id: 2 desc: Backcover Color
id: 3 desc: Unlock Count
id: 4 desc: Custom Flag
id: 5 desc: Cal Reboot Count
id: 6 desc: Normal Reboot Count
id: 7 desc: A/B Normal Reboot Count
id: 8 desc: Update Count
id: 9 desc: Fastboot Count
id: 11 desc: Restart Other Count
id: 12 desc: Index Time Create Key
id: 13 desc: Index Time Pass Key
id: 14 desc: Index Time Fail Key
id: 16 desc: Boot Type
id: 17 desc: Online Cfg Test Env
id: 19 desc: SMT Download State
id: 20 desc: Upgrade Download State
id: 21 desc: Recondition Flag
id: 23 desc: Enc Carrier ID
id: 24 desc: Enc Target SW ID
id: 25 desc: Enc Sale Channel ID
id: 26 desc: unknow
```

### Read Int
```
usage: op8t_param.py read [-h] -f FILE [-ne] [-np] [id]

positional arguments:
  id                    id

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  dumped param image file
  -ne, --not-prmec      ro.boot.prmec
  -np, --not-primary    use backup block, if not, use primary
```

#### Example
Read Cyberpunk edition flag.
```
➜  python op8t_param.py read -f param.bin 4

id: 4 offset: 0x4c4a0 value: 0 (0x0) desc: Custom Flag (primary) (prmec)
```

### Write Int
```
usage: op8t_param.py write [-h] -f FILE -o OUT [-ne] [-np] id value

positional arguments:
  id                    id
  value                 value

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  dumped param image file
  -o OUT, --out OUT     new param image file
  -ne, --not-prmec      ro.boot.prmec
  -np, --not-primary    use backup block, if not, use primary
```

#### Example

Write Cyberpunk edition flag.
```
➜  python op8t_param.py write -f param.bin -o param2.bin 4 8

id: 4 offset: 0x4c4a0 value: 0 (0x0) desc: Custom Flag (primary) (prmec)
change value 0x0 to 0x8
save file to param2.bin
```

## Convert to Cyberpunk Edition
1. dump param partition
```
➜  adb shell
➜  su
➜  dd if=/dev/block/by-name/param of=/sdcard/param.bin
➜  exit
➜  exit
➜  adb pull /sdcard/param.bin ./
```
2. Write Cyberpunk Edition flag
```
➜  python op8t_param.py write -f param.bin -o param2.bin 4 8
```
3. flash param partition
```
➜  adb push ./param2.bin /sdcard/
➜  adb shell
➜  su
➜  dd if=/sdcard/param2.bin of=/dev/block/by-name/param
```
or you can use fastboot flash param partition
```
➜  adb reboot bootloader
➜  fastboot flash param param2.bin
```
3. reboot

## License
MIT
