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

        return self.memory.get(address,0) #?

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

    def get_register(self,value):
        return self.reg_map[value]

    def execute_halt(self):
        self.stat = 2
        self.PC += 1

    def execute_nop(self):
        self.PC += 1

    def execute_rrmovq_and_cmov(self):
        head = self.read_byte(self.PC)
        second = head & 0xf

        reg = self.read_byte(self.PC + 1)
        rA = self.get_register(reg >> 4)
        rB = self.get_register(reg & 0xf)
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

        self.PC += 2

    def execute_irmovq(self):

        reg = self.read_byte(self.PC + 1)
        rB = self.get_register(reg & 0xf)
        value = self.read_word(self.PC + 2 , 8)
        self.registers[rB] = value

        self.PC += 10

    def execute_rmmovq(self):

        reg = self.read_byte(self.PC + 1)
        rA = self.get_register(reg >> 4)
        rB = self.get_register(reg & 0xf)
        
        offset = self.read_word(self.PC + 2, 8)

        reg_value = self.registers[rA]
        base_addr = self.registers[rB]
        addr = base_addr + offset

        self.write_word(addr,reg_value,8)

        self.PC += 10
        
    def execute_mrmovq(self):

        reg = self.read_byte(self.PC + 1)
        rA = self.get_register(reg >> 4)
        rB = self.get_register(reg & 0xf)
        
        offset = self.read_word(self.PC + 2, 8)

        base_addr = self.registers[rA]
        reg_value = self.registers[rB]
        addr = base_addr + offset

        self.write_word(addr,reg_value,8)

        self.PC += 10

    def execute_calc(self):

        head = self.read_byte(self.PC)
        second = head & 0xf

        reg = self.read_byte(self.PC + 1)
        rA = self.get_register(reg >> 4)
        rB = self.get_register(reg & 0xf)
        rA_value = self.registers[rA]
        rB_value = self.registers[rB]

        if second == 0:  #addq
            
            sum_value = rA_value + rB_value
            self.registers[rB] = sum_value
            #更新条件码
            self.ZF = 1 if sum_value == 0 else 0
            self.SF = 1 if (sum_value & 0x8000000000000000) != 0 else 0
            self.OF = 1 if (rA_value < 0 and rB_value < 0 and sum_value > 0) or \
                           (rA_value > 0 and rB_value > 0 and sum_value < 0) else 0
        elif second == 1:  #subq

            sub_value = rB_value - rA_value
            self.registers[rB] = sub_value
            #更新条件码
            self.ZF = 1 if sub_value == 0 else 0
            self.SF = 1 if (sub_value & 0x8000000000000000) != 0 else 0
            self.OF = 1 if (rA_value < 0 and rB_value > 0 and sum_value < 0) or \
                           (rA_value > 0 and rB_value < 0 and sum_value > 0) else 0
        elif second == 2:  #andq

            and_value = rA_value & rB_value
            self.registers[rB] = and_value
            #更新条件码
            self.ZF = 1 if and_value == 0 else 0
            self.SF = 1 if (and_value & 0x8000000000000000) != 0 else 0
            self.OF = 0
        elif second == 3:  #xorq

            xor_value = rA_value ^ rB_value
            self.registers[rB] = xor_value
            #更新条件码
            self.ZF = 1 if xor_value == 0 else 0
            self.SF = 1 if (xor_value & 0x8000000000000000) != 0 else 0
            self.OF = 0

        self.PC += 2
        

    def execute_jump(self):

        head = self.read_byte(self.PC)
        second = head & 0xf

        addr = self.read_word(self.PC + 1,8)

        if second == 0:  #jmp
            self.PC = addr
        elif second == 1:  #jle
            if self.SF != self.OF or self.ZF == 1:
                self.PC = addr
            else:
                self.PC += 9
        elif second == 2:  #jl
            if self.SF != self.OF:
                self.PC = addr
            else:
                self.PC += 9
        elif second == 3:  #je
            if self.ZF == 1:
                self.PC = addr
            else:
                self.PC += 9
        elif second == 4:  #jne
            if self.ZF == 0:
                self.PC = addr
            else:
                self.PC += 9
        elif second == 5:  #jge
            if self.SF == self.OF:
                self.PC = addr
            else:
                self.PC += 9
        elif second == 6:  #jg
            if self.SF == self.OF and self.ZF == 0:
                self.PC = addr
            else:
                self.PC += 9
        

    def execute_callq(self):

        target_addr = self.read_word(self.PC + 1)
        next_addr = self.PC + 9

        rsp_value = self.registers["rsp"]
        new_rsp = rsp_value - 8
        
        self.write_word(new_rsp,next_addr,8)
        self.registers["rsp"] = new_rsp

        self.PC = target_addr
        

    def execute_ret(self):
        
        rsp_value = self.registers["rsp"]
        ret_addr = self.read_word(rsp_value,8)

        new_rsp = rsp_value + 8
        self.registers["rsp"] = new_rsp

        self.PC = ret_addr



    def execute_pushq(self):
        reg_byte = self.read_byte(self.PC + 1)
        rA = self.get_register(reg_byte >> 4)  
        value = self.registers[rA]
        rsp_value = self.registers["rsp"]
        new_rsp = rsp_value - 8
        self.registers["rsp"] = new_rsp #先移动，再赋值
        self.write_word(new_rsp, value) #默认值8，栈操作默认是8字节
        self.PC += 2

    def execute_popq(self):
        reg_byte = self.read_byte(self.PC + 1)
        rA = self.get_register(reg_byte >> 4)  # 高4位是寄存器编号
        rsp_value = self.registers["rsp"]
        value = self.read_word(rsp_value)
        new_rsp = rsp_value + 8
        self.registers[rA] = value
        self.registers["rsp"] = new_rsp #先赋值，再移动栈帧
        self.PC += 2

    def run(self):
        pass

if __name__ == "__main__":
    pass
