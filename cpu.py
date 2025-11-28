import sys
import re
import json


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
        self.head_map = {
            0x0: self.execute_halt,
            0x1: self.execute_nop,
            0x2: self.execute_rrmovq_and_cmov,
            0x3: self.execute_irmovq,
            0x4: self.execute_rmmovq,
            0x5: self.execute_mrmovq,
            0x6: self.execute_calc,
            0x7: self.execute_jump,
            0x8: self.execute_callq,
            0x9: self.execute_ret,
            0xa: self.execute_pushq,
            0xb: self.execute_popq
        }
        self.stat = 1
        self.memory = {}
        self.ZF = 1  #从示例输出可知，在初始化时ZF默认为1
        self.SF = 0 
        self.OF = 0

        #记录执行历史
        self.states = []

    def parse_yo_file(self,content):
        instructions = []

        for line in content.split('\n'):
            #去除注释
            code = line.split('|')[0].strip()

            #针对文件中可能不出现代码只有注释的行，直接跳过
            if code == "":
                continue

            addr = code.split(':')[0].strip()
            machine_code = code.split(':')[1].strip()

            #有些行是一个函数的地址开头，无机器码，也直接跳过
            if machine_code == "":
                continue

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
        #从PC读取头一个byte
        try:
            head = self.memory[self.PC]  # 直接访问，如果不存在会抛出KeyError
            first = (head >> 4) & 0xf
            
            self.head_map[first]()  

        except KeyError:
            self.stat = 3  # 内存访问错误


    def read_byte(self,address):

        return self.memory.get(address,0) 

    def read_word(self, address, size=8):
        
        #小端法读取8个byte
        value = 0
        for i in range(size):
            byte_val = self.read_byte(address + i)
            value |= (byte_val << (i * 8))
        
        return value & 0xFFFFFFFFFFFFFFFF

    def write_byte(self,address,value):
        self.memory[address] = value & 0xff

    def write_word(self,address,value,size=8):
        for i in range(size):
            self.memory[address+i] = (value >> 8*i) & 0xff

    def get_register(self,value):
        return self.reg_map[value]

    def execute_halt(self):
        self.stat = 2
        #halt不改变PC

    def execute_nop(self):
        self.PC += 1

    def execute_rrmovq_and_cmov(self):
        head = self.read_byte(self.PC)
        second = head & 0xf

        reg = self.read_byte(self.PC + 1)
        rA = self.get_register((reg >> 4) & 0xf)
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
        self.registers[rB] = value & 0xFFFFFFFFFFFFFFFF

        self.PC += 10

    def execute_rmmovq(self):

        reg = self.read_byte(self.PC + 1)
        rA = self.get_register((reg >> 4) & 0xf)
        rB = self.get_register(reg & 0xf)
        
        offset = self.read_word(self.PC + 2, 8)

        reg_value = self.registers[rA]
        base_addr = self.registers[rB]
        addr = (base_addr + offset) & 0xFFFFFFFFFFFFFFFF

        self.write_word(addr,reg_value,8)

        self.PC += 10
        
    def execute_mrmovq(self):

        reg = self.read_byte(self.PC + 1)
        rA = self.get_register((reg >> 4) & 0xf)
        rB = self.get_register(reg & 0xf)
        
        offset = self.read_word(self.PC + 2, 8)

        base_addr = self.registers[rB]
        addr = (base_addr + offset) & 0xFFFFFFFFFFFFFFFF

        value = self.read_word(addr,8)
        self.registers[rA] = value

        self.PC += 10

    def execute_calc(self):

        head = self.read_byte(self.PC)
        second = head & 0xf

        reg = self.read_byte(self.PC + 1)
        rA = self.get_register((reg >> 4) & 0xf)
        rB = self.get_register(reg & 0xf)
        rA_value = self.registers[rA]
        rB_value = self.registers[rB]

        if second == 0:  #addq
            
            sum_value = (rA_value + rB_value) & 0xFFFFFFFFFFFFFFFF
            self.registers[rB] = sum_value
            #更新条件码
            self.ZF = 1 if sum_value == 0 else 0
            self.SF = 1 if (sum_value & 0x8000000000000000) != 0 else 0
            self.OF = 1 if (rA_value < 0 and rB_value < 0 and sum_value > 0) or \
                           (rA_value > 0 and rB_value > 0 and sum_value < 0) else 0
        elif second == 1:  #subq

            sub_value = (rB_value - rA_value) & 0xFFFFFFFFFFFFFFFF
            self.registers[rB] = sub_value
            #更新条件码
            self.ZF = 1 if sub_value == 0 else 0
            self.SF = 1 if (sub_value & 0x8000000000000000) != 0 else 0
            self.OF = 1 if (rA_value < 0 and rB_value > 0 and sub_value < 0) or \
                           (rA_value > 0 and rB_value < 0 and sub_value > 0) else 0
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
        new_rsp = (rsp_value - 8) & 0xFFFFFFFFFFFFFFFF
        self.registers["rsp"] = new_rsp
        if new_rsp & 0x8000000000000000 != 0:
            self.stat = 3
        else:
        
            self.write_word(new_rsp,next_addr,8)

            self.PC = target_addr
        

    def execute_ret(self):
        
        rsp_value = self.registers["rsp"]
        ret_addr = self.read_word(rsp_value,8)

        new_rsp = (rsp_value + 8) & 0xFFFFFFFFFFFFFFFF
        self.registers["rsp"] = new_rsp

        self.PC = ret_addr



    def execute_pushq(self):

        reg_byte = self.read_byte(self.PC + 1)
        rA = self.get_register((reg_byte >> 4) & 0xf)  
        value = self.registers[rA]
        rsp_value = self.registers["rsp"]

        new_rsp = (rsp_value - 8) & 0xFFFFFFFFFFFFFFFF
        self.registers["rsp"] = new_rsp #先移动，再赋值
        if new_rsp & 0x8000000000000000 != 0:
            self.stat = 3
        else:

            self.write_word(new_rsp, value) #默认值8，栈操作默认是8字节

            self.PC += 2
    
    def execute_popq(self):
        reg_byte = self.read_byte(self.PC + 1)
        rA = self.get_register((reg_byte >> 4) & 0xf)  

        rsp_value = self.registers["rsp"]
        value = self.read_word(rsp_value)

        new_rsp = (rsp_value + 8) & 0xFFFFFFFFFFFFFFFF
        
        if rA != "rsp":
            self.registers[rA] = value  
            self.registers["rsp"] = new_rsp #正常逻辑：先赋值，再移动栈帧
        else:
            self.registers[rA] = value #罕见逻辑：若popq rsp,则只把值赋给rsp,不进行额外的栈指针的移动
              
        self.PC += 2
    
    #将64位无符号整数转换为有符号整数
    def to_signed(self, value):
        
        if value & 0x8000000000000000:
            return value - 0x10000000000000000
        return value

    def save_states(self):
        #符号码
        CC = {
            "OF": self.OF,
            "SF": self.SF,
            "ZF": self.ZF
        }
        #内存
        mem_state = {}
        mem_bytes = sorted(self.memory.keys())
        processed_blocks = set()

        for mem_byte in mem_bytes:

            mem_byte_head = mem_byte - (mem_byte % 8)  #找到每8个字节的头字节
            if mem_byte_head not in processed_blocks:
                value = 0
                processed_blocks.add(mem_byte_head)
                for i in range(8):
                    new_value = self.memory.get(mem_byte_head + i,0) #小端法
                    value |= (new_value << 8*i)
                if value:  #只存储非0值
                    # 转换为有符号表示
                    signed_value = self.to_signed(value)
                    signed_mem_byte_head = self.to_signed(mem_byte_head)
                    mem_state[signed_mem_byte_head] = signed_value
                    
        # 寄存器状态（按字母顺序排序并转换为有符号）
        reg_state = {}
        for reg_name in sorted(self.registers.keys()):
            reg_state[reg_name] = self.to_signed(self.registers[reg_name])

        #本次指令结束后所有部分的状态
        all_state = {
            "CC": CC,
            "MEM": mem_state,
            "PC": self.PC,
            "REG": reg_state,
            "STAT": self.stat
        }
        self.states.append(all_state)

    def run(self,program_input):
        #读文件
        instructions = self.parse_yo_file(program_input)
        
        
        # 设置初始PC为第一条指令的地址
        self.PC = instructions[0]['address']
        
        # 执行循环
        while self.stat == 1:  # 正常执行
            # 解码并执行指令
            self.fetch()
            
            # 保存执行后状态
            self.save_states()
            
            # 检查是否应该停止
            if self.stat != 1:
                break
        
        return self.states



def main():
    #读取输入的文件
    input_file = sys.stdin.read()

    CPU = Simulator()

    states_history = CPU.run(input_file)
    json.dump(states_history,sys.stdout,indent=4)

if __name__ == "__main__":
    main()
