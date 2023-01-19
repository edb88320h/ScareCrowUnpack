import pefile
from capstone import *
from struct import pack
from Crypto.Cipher import AES
from base64 import b64decode
from binascii import unhexlify
import argparse
import click

class ScareCrowDecrypt():
    def __init__(self):
        self.iv = b""
        self.key = b""
        self.code = b""
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.data_encr = b""

    def decrypt(self, file: str):
        aes = AES.new(b64decode(self.key), AES.MODE_CBC, b64decode(self.iv))
        data_final = b64decode(aes.decrypt(b64decode(self.data_encr)))
        binary_final = unhexlify(data_final)
        print(f"[+] decrypt the data, payload data in {file}_payload_decr.bin")
        outPld = open(f"{file}_payload_decr.bin", "wb")
        outPld.write(binary_final)
        exit(0)

    def fileparse(self, pe: pefile.PE, file: str):
        data = pe.get_memory_mapped_image(ImageBase=pe.OPTIONAL_HEADER.ImageBase)
        print("[+] Load binary as PE-File")
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_ava = pe.OPTIONAL_HEADER.ImageBase
        for cnt in range(len(data) - 5):
            if data[cnt] == 0x31 and data[cnt + 2] == 0x31 and data[cnt + 4] == 0x31 and data[cnt + 6] == 0x48 and data[cnt + 13] == 0xbe:  # find start of decryption function in binary
                print("[+] find a start of function")
                j = cnt

                while 1:
                    if data[j] == 0x48 and data[j + 1] == 0x81 and data[j + 2] == 0xc4 and data[j + 5] == 0x00 and data[j + 6] == 0x00 and data[j + 7] == 0xc3:  # find end of function
                        break
                    else:
                        self.code += pack("B", data[j])
                        j += 1
                for n in self.md.disasm(self.code, ep_ava + cnt):
                    if n.op_str.find(
                            "rip +") != -1 and n.mnemonic == "lea":  # search for an instruction that puts an offset on the data in the register
                        try:
                            addr = n.address + int(n.op_str.split("rip +")[1][:-1],16) + 7  # tried to get an offset to data
                        except IndexError:
                            print("something wrong")
                    if n.op_str.find("0x18") != -1 and n.op_str.find("]") == -1:  # search for the iv
                        size = int(n.op_str.split(", ")[1], 16)  # get iv size
                        self.iv = pe.get_data(addr - ep_ava)[:size]  # get iv in the image
                        print(f"[+] find an iv for AES {self.iv}")
                        if self.key != b"":
                            self.decrypt(file)
                    if n.op_str.find("0x2c") != -1:  # search for the key
                        size = int(n.op_str.split(", ")[1], 16)  # get key size
                        self.key = pe.get_data(addr - ep_ava)[:size]  # get key data
                        print(f"[+] find a key for AES {self.key}")
                        if self.iv != b"":
                            self.decrypt(file)
                    if n.op_str.find("esi") != -1:  # search for any chunk of data
                        size = int(n.op_str.split(", ")[1], 16)  # get chunk size
                        data = pe.get_data(addr - ep_ava)[:size]  # find data in the image
                        self.data_encr += data  # make full binary string


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--f")
    args = parser.parse_args()
    file = args.f
    if file != None:
        fd = open(file, 'rb')
    else:
        exit(0)
    unpacker = ScareCrowDecrypt()
    pe = pefile.PE(file)
    unpacker.fileparse(pe, file)
