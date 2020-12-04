#coding=utf-8 

import struct
import hashlib
import argparse
#pycryptodome
from Crypto.Cipher import AES

class OPParam:
    def __init__(self, data: bytearray):
        self.key = b'\x30\x30\x30\x4F\x6E\x65\x50\x6C\x75\x73\x38\x31\x38\x30\x30\x30'
        self.iv = b'\x56\x2E\x17\x99\x6D\x09\x3D\x28\xDD\xB3\xBA\x69\x5A\x2E\x6F\x58'
        self.data = data

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        return bytearray(cipher.encrypt(data))

    def decrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        return bytearray(cipher.decrypt(data))

    def read_block(self, sid, primary):
        if not primary:
            block_start = sid << 10
        else:
            block_start = (sid+0x200) << 10
        block = self.data[block_start:block_start+0x1000]
        if block[0:4] == b'\x6A\x64\xAD\xA0':
            header = block[0:0x400]
            content = block[0x400:]
            return header+self.decrypt(content)
        else:
            return block

    def read_int(self, offset, primary=True):
        sid = (offset >> 10) & 0x3FFFFC
        block = self.read_block(sid, primary)
        offset = offset & 0xfff
        res = block[offset:offset+4]
        return struct.unpack('<I', res)[0]

    def write_int(self, offset, value, primary=True):
        sid = (offset >> 10) & 0x3FFFFC
        block = self.read_block(sid, primary)
        offset = offset & 0xfff
        value = struct.pack('I', value)
        block[offset:offset+4] = value
        if block[0:4] == b'\x6A\x64\xAD\xA0':
            header = block[0:0x400]
            content = block[0x400:]
            block = header+self.encrypt(content)
        hash = hashlib.md5(block[0x400:])
        block[0x80:0x90] = hash.digest()
        if not primary:
            block_start = sid << 10
        else:
            block_start = (sid+0x200) << 10
        self.data[block_start:block_start+0x1000]=block


ids_info = {
    # id: [normal,prmec,name,desc]
    1: [0x31A4,  0x4B480,  "INTRANET"               ,"Intranet"                ],
    2: [0x288C,  0x0288C,  "BACKCOVER_COLOR"        ,"Backcover Color"         ],
    3: [0x3428,  0x03428,  "UNLOCK_COUNT"           ,"Unlock Count"            ],
    4: [0x2884,  0x4C4A0,  "CUST_FLAG"              ,"Custom Flag"             ],
    5: [0x2888,  0x02888,  "CAL_REBOOT_COUNT"       ,"Cal Reboot Count"        ],
    6: [0x3418,  0x03418,  "NORMAL_REBOOT_COUNT"    ,"Normal Reboot Count"     ],
    7: [0x341C,  0x0341C,  "ABNORMAL_REBOOT_COUNT"  ,"A/B Normal Reboot Count" ],
    8: [0x3420,  0x03420,  "UPDATE_COUNT"           ,"Update Count"            ],
    9: [0x3424,  0x03424,  "FASTBOOT_COUNT"         ,"Fastboot Count"          ],
    #10:[0x0000,  0x00000,  "RESTART_08_COUNT"       ,"Restart 08 Count"        ],
    11:[0x255C,  0x0255C,  "RESTART_OTHER_COUNT"    ,"Restart Other Count"     ],
    12:[0x2C20,  0x4E4E0,  "INDEX_TIME_CREATE_KEY"  ,"Index Time Create Key"   ],
    13:[0x2CE4,  0x4E5A4,  "INDEX_TIME_PASS_KEY"    ,"Index Time Pass Key"     ],
    14:[0x2DA8,  0x4E668,  "INDEX_TIME_FAIL_KEY"    ,"Index Time Fail Key"     ],
    #15:[0x0000,  0x00000,  "HDCP_STATUS"            ,"HDCP Status"             ],
    16:[0x31A8,  0x4B484,  "BOOT_TYPE"              ,"Boot Type"               ],
    17:[0x0420,  0x4B488,  "ONLINE_CFG_TEST_ENV"    ,"Online Cfg Test Env"     ],
    #18:[0x0000,  0x00000,  "ENC_IMEI_SET_FLAG"      ,"Enc IMEI Set Flag"       ],
    19:[0x3030,  0x03030,  "SMT_DOWNLOAD_STATE"     ,"SMT Download State"      ],
    20:[0x30F0,  0x030F0,  "UPGRADE_DOWNLOAD_STATE" ,"Upgrade Download State"  ],
    21:[0x0000,  0x4D494,  "RECONDITION_FLAG"       ,"Recondition Flag"        ],
    #22:[0x0000,  0x00000,  "ENC_MEID_SET_FLAG"      ,"Enc MEID Set Flag"       ],
    23:[0x0000,  0x4C4A8,  "ENC_CARRIER_ID"         ,"Enc Carrier ID"          ],
    24:[0x0000,  0x4B48C,  "ENC_TARGET_SW_ID"       ,"Enc Target SW ID"        ],
    25:[0x0000,  0x4D4FC,  "ENC_SALE_CHANNEL_ID"    ,"Enc Sale Channel ID"     ],
    26:[0x0000,  0x4B490,  "UNKNOW"                 ,"unknow"                  ],
}

def get_offset(id, prmec):
    if prmec:
        index = 1
    else:
        index = 0
    if id in ids_info:
        offset = ids_info[id][index]
        if offset != 0:
            name = ids_info[id][2]
            desc = ids_info[id][3]
            return offset,name,desc
    else:
        print('invalid id')
        return -1,''
    return 0,''

def read_param_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
        if data[0:8] == b'\x50\x52\x4F\x44\x55\x43\x54\x00':
            return True,bytearray(data)
    return False,b'param image file check error'

def list_ids(args):
    for id in ids_info:
        print('id: {} desc: {}'.format(id, ids_info[id][3]))

def read_id_one(args):
    offset,_name,desc = get_offset(args.id, args.prmec)
    if args.primary:
        desc += ' (primary)'
    else:
        desc += ' (backup)'
    if args.prmec:
        desc += ' (prmec)'
    else:
        desc += ' (not prmec)'

    if offset > 0:
        r,d = read_param_file(args.file)
        if r:
            op = OPParam(d)
            value = op.read_int(offset, args.primary)
            print('id: {} offset: {} value: {} ({}) desc: {}'.format(args.id, hex(offset), value, hex(value), desc))
        else:
            print(d)
    else:
        print('id: {} desc: {} not exist'.format(args.id, desc))


def read_id(args):
    if args.id == -1:
        for id in ids_info:
            args.id = id
            read_id_one(args)
    else:
        read_id_one(args)


def write_id(args):
    offset,_name,desc = get_offset(args.id, args.prmec)
    if args.primary:
        desc += ' (primary)'
    else:
        desc += ' (backup)'
    if args.prmec:
        desc += ' (prmec)'
    else:
        desc += ' (not prmec)'

    if offset > 0:
        r,d = read_param_file(args.file)
        if r > 0:
            op = OPParam(d)
            value = op.read_int(offset, args.primary)
            print('id: {} offset: {} value: {} ({}) desc: {}'.format(args.id, hex(offset), value, hex(value), desc))
            print('change value {} to {}'.format(hex(value), hex(args.value)))
            op.write_int(offset, args.value, args.primary)
            with open(args.out, 'wb') as f:
                f.write(op.data)
            print('save file to {}'.format(args.out))
    else:
        print('id: {} desc: {} not exist'.format(args.id, desc))

def main():
    parser = argparse.ArgumentParser(
        description='OnePlus 8T param tools',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    subparsers = parser.add_subparsers()

    parser_list = subparsers.add_parser('list', allow_abbrev=True, help='list available ids')
    parser_list.set_defaults(func=list_ids)

    parser_read = subparsers.add_parser('read', help='read')
    parser_read.add_argument('id', type=int, nargs='?', default=-1, help='id')
    parser_read.add_argument('-f', '--file', required=True, help='dumped param image file')
    parser_read.add_argument('-ne', '--not-prmec', dest='prmec', action='store_false', help='ro.boot.prmec')
    parser_read.add_argument('-np', '--not-primary', dest='primary', action='store_false', help='use backup block, if not, use primary')
    parser_read.set_defaults(func=read_id)

    parser_write = subparsers.add_parser('write', help='write')
    parser_write.add_argument('id', type=int, help='id')
    parser_write.add_argument('value', type=int, help='value')
    parser_write.add_argument('-f', '--file', required=True, help='dumped param image file')
    parser_write.add_argument('-o', '--out', required=True, help='new param image file')
    parser_write.add_argument('-ne', '--not-prmec', dest='prmec', action='store_false', help='ro.boot.prmec')
    parser_write.add_argument('-np', '--not-primary', dest='primary', action='store_false', help='use backup block, if not, use primary')
    parser_write.set_defaults(func=write_id)

    options = parser.parse_args()
    if 'func' in options:
        options.func(options)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
