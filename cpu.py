import sys
import re
import json

cpu = Simulator()
cpu.PC

class Simulator:
    def __init__(self):
        #初始化
        self.PC = 0
        self.registers = {
            'rax': 0, 'rcx': 0, 'rdx': 0, 'rbx': 0,
            'rsp': 0, 'rbp': 0, 'rsi': 0, 'rdi': 0,
            'r8': 0, 'r9': 0, 'r10': 0, 'r11': 0,
            'r12': 0, 'r13': 0, 'r14': 0
        }
        self.reg_map = {
            0: 'rax', 1: 'rcx', 2: 'rdx', 3: 'rbx',
            4: 'rsp', 5: 'rbp', 6: 'rsi', 7: 'rdi',
            8: 'r8', 9: 'r9', 10: 'r10', 11: 'r11',
            12: 'r12', 13: 'r13', 14: 'r14'
        }
        self.stat = 1
        self.memory = {}
        self.ZF = 0
        self.SF = 0 
        self.OF = 0

        #记录执行历史
        self.states = []

    def parse_yo_file(self,content):
        instructions = []

        for line in content.split('\n'):
            code = line.split('|')[0].strip()

            addr = code.split(':')[0].strip()
            machine_code = code.split(':')[1].strip()

            addr = int(addr,16)
            machine_bytes = bytes.fromhex(machine_code)
            for i, byte in enumerate(machine_bytes):
                self.memory[addr + i] = byte

            instructions.append({
                "address":addr,
                "machine_code":machine_code
            })

        return instructions
        
    def fetch(self):

        head = self.memory.get(self.PC)

        first = head >> 4
        second = head & 0xf

        head_map = {
            0x0: execute_halt,
            0x1: execute_nop,
            0x2: execute_rrmovq_and_cmov,
            0x3: execute_irmovq,
            0x4: execute_rmmovq,
            0x5: execute_mrmovq,
            0x6: execute_calc,
            0x7: execute_jump,
            0x8: execute_callq,
            0x9: execute_ret,
            0xa: execute_pushq,
            0xb: execute_popq
        }
        
        head_map[first]



    def decode(self,key):

        return self.registers.get(key)

    def read_byte(self,address):

        return self.memory(address,0)

    def read_word(self, address, size=8):
        
        """从内存读取一个字（小端序）8个字节"""
        value = 0
        for i in range(size):
            byte_val = self.read_byte(address + i,0)
            value |= (byte_val << (i * 8))
        return value

    def write_byte(self,address,value):
        self.memory[address] = value & 0xff

    def write_word(self,address,value,size=8):
        for i in range(size):
            self.memory[address+i] = (value >> 8*i) & 0xff

    def get_rigister(self,value):
        return self.reg_map(value,0)

    def execute_halt(self):
        self.stat = 2
        self.PC += 1

    def execute_nop(self):
        self.PC += 1

    def execute_rrmovq_and_cmov(self):
        head = self.read_byte(self.PC)
        second = head & 0xf

        rig = self.read_byte(self.PC + 1)
        rA = self.get_rigister(rig >> 4)
        rB = self.get_rigister(rig & 0xf)
        if second == 0:
            self.registers[rB] = self.registers[rA]
        elif second == 1:  #le
            if self.SF != self.OF or self.ZF == 1:
                self.registers[rB] = self.registers[rA]
        elif second == 2:  #l
            if self.SF != self.OF:
                self.registers[rB] = self.registers[rA]
        elif second == 3:  #e
            if self.ZF == 1:
                self.registers[rB] = self.registers[rA]
        elif second == 4:  #ne
            if self.ZF == 0:
                self.registers[rB] = self.registers[rA]
        elif second == 5:  #ge
            if self.SF == self.OF:
                self.registers[rB] = self.registers[rA]
        elif second == 6:  #g
            if self.SF == self.OF and self.ZF == 0:
                self.registers[rB] = self.registers[rA]


    def execute_irmovq(self):
        

    def execute_rmmovq(self):
        pass
        
    def execute_mrmovq(self):
        pass

    def execute_calc(self):
        pass

    def execute_jump(self):
        pass

    def execute_callq(self):
        pass

    def execute_ret(self):
        pass

    def execute_pushq(self):
        pass

    def execute_popq(self,second):
        pass

    def run(self):
        pass

if __name__ == "__main__":
    pass
