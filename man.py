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
        
        # 添加执行步数限制，防止无限循环
        self.max_steps = 10000
        self.step_count = 0
        
        # 缓存上一次保存的状态，避免重复保存相同状态
        self.last_state = None

    def parse_yo_file(self,content):
        instructions = []

        for line in content.split('\n'):
            #去除注释
            code = line.split('|')[0].strip()

            #针对文件中可能不出现代码只有注释的行，直接跳过
            if code == "":
                continue

            # 检查是否是标签行（只有地址没有机器码）
            if ':' not in code:
                continue
                
            parts = code.split(':', 1)
            if len(parts) < 2:
                continue
                
            addr_str, machine_code_str = parts
            addr_str = addr_str.strip()
            machine_code_str = machine_code_str.strip()

            # 跳过只有标签没有机器码的行
            if machine_code_str == "":
                continue

            try:
                addr = int(addr_str, 16)
                # 移除机器码中的空格
                machine_code_str = machine_code_str.replace(' ', '')
                machine_bytes = bytes.fromhex(machine_code_str)
                for i, byte in enumerate(machine_bytes):
                    self.memory[addr + i] = byte

                instructions.append({
                    "address": addr,
                    "machine_code": machine_code_str
                })
            except (ValueError, IndexError):
                continue

        return instructions
        
    def fetch(self):
        #从PC读取头一个byte
        try:
            head = self.memory.get(self.PC, 0)  # 使用get避免KeyError
            if head == 0 and self.PC not in self.memory:
                self.stat = 3  # 内存访问错误
                return
                
            first = (head >> 4) & 0xf
            
            if first in self.head_map:
                self.head_map[first]()  
            else:
                self.stat = 3  # 无效指令

        except Exception:
            self.stat = 3  # 内存访问错误


    def read_byte(self,address):
        return self.memory.get(address, 0) 

    def read_word(self, address, size=8):
        #小端法读取8个byte
        value = 0
        for i in range(size):
            byte_val = self.read_byte(address + i)
            value |= (byte_val << (i * 8))
        
        return value

    def write_byte(self,address,value):
        self.memory[address] = value & 0xff

    def write_word(self,address,value,size=8):
        for i in range(size):
            self.memory[address+i] = (value >> (8*i)) & 0xff

    def get_register(self,value):
        return self.reg_map.get(value, f"r{value}")

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
            # 普通rrmovq
            self.registers[rB] = self.registers[rA]
        else:
            # 条件移动
            condition_met = False
            if second == 1:  #le
                condition_met = (self.SF != self.OF) or (self.ZF == 1)
            elif second == 2:  #l
                condition_met = (self.SF != self.OF)
            elif second == 3:  #e
                condition_met = (self.ZF == 1)
            elif second == 4:  #ne
                condition_met = (self.ZF == 0)
            elif second == 5:  #ge
                condition_met = (self.SF == self.OF)
            elif second == 6:  #g
                condition_met = (self.SF == self.OF) and (self.ZF == 0)
            
            if condition_met:
                self.registers[rB] = self.registers[rA]

        self.PC += 2

    def execute_irmovq(self):
        reg = self.read_byte(self.PC + 1)
        rB = self.get_register(reg & 0xf)
        value = self.read_word(self.PC + 2, 8)
        self.registers[rB] = value
        self.PC += 10

    def execute_rmmovq(self):
        reg = self.read_byte(self.PC + 1)
        rA = self.get_register((reg >> 4) & 0xf)
        rB = self.get_register(reg & 0xf)
        
        offset = self.read_word(self.PC + 2, 8)
        reg_value = self.registers[rA]
        base_addr = self.registers[rB]
        addr = (base_addr + offset) & 0xFFFFFFFFFFFFFFFF

        self.write_word(addr, reg_value, 8)
        self.PC += 10
        
    def execute_mrmovq(self):
        reg = self.read_byte(self.PC + 1)
        rA = self.get_register((reg >> 4) & 0xf)
        rB = self.get_register(reg & 0xf)
        
        offset = self.read_word(self.PC + 2, 8)
        base_addr = self.registers[rB]
        addr = (base_addr + offset) & 0xFFFFFFFFFFFFFFFF

        value = self.read_word(addr, 8)
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

        result = 0
        if second == 0:  #addq
            result = (rA_value + rB_value) & 0xFFFFFFFFFFFFFFFF
            self.registers[rB] = result
        elif second == 1:  #subq
            result = (rB_value - rA_value) & 0xFFFFFFFFFFFFFFFF
            self.registers[rB] = result
        elif second == 2:  #andq
            result = rA_value & rB_value
            self.registers[rB] = result
        elif second == 3:  #xorq
            result = rA_value ^ rB_value
            self.registers[rB] = result

        #更新条件码
        self.ZF = 1 if result == 0 else 0
        self.SF = 1 if (result & 0x8000000000000000) != 0 else 0
        
        # 溢出标志计算
        if second == 0:  #addq
            # 检查有符号溢出：两个正数相加得负数，或两个负数相加得正数
            a_sign = rA_value & 0x8000000000000000
            b_sign = rB_value & 0x8000000000000000
            result_sign = result & 0x8000000000000000
            self.OF = 1 if (a_sign == b_sign) and (a_sign != result_sign) else 0
        elif second == 1:  #subq
            # 检查有符号溢出：正数减负数得负数，或负数减正数得正数
            a_sign = rA_value & 0x8000000000000000
            b_sign = rB_value & 0x8000000000000000
            result_sign = result & 0x8000000000000000
            self.OF = 1 if (b_sign != a_sign) and (b_sign != result_sign) else 0
        else:  #andq, xorq
            self.OF = 0

        self.PC += 2
        

    def execute_jump(self):
        head = self.read_byte(self.PC)
        second = head & 0xf

        addr = self.read_word(self.PC + 1, 8)

        jump_taken = False
        if second == 0:  #jmp
            jump_taken = True
        elif second == 1:  #jle
            jump_taken = (self.SF != self.OF) or (self.ZF == 1)
        elif second == 2:  #jl
            jump_taken = (self.SF != self.OF)
        elif second == 3:  #je
            jump_taken = (self.ZF == 1)
        elif second == 4:  #jne
            jump_taken = (self.ZF == 0)
        elif second == 5:  #jge
            jump_taken = (self.SF == self.OF)
        elif second == 6:  #jg
            jump_taken = (self.SF == self.OF) and (self.ZF == 0)

        if jump_taken:
            self.PC = addr
        else:
            self.PC += 9
        

    def execute_callq(self):
        target_addr = self.read_word(self.PC + 1, 8)
        next_addr = self.PC + 9

        rsp_value = self.registers["rsp"]
        new_rsp = (rsp_value - 8) & 0xFFFFFFFFFFFFFFFF
        
        self.write_word(new_rsp, next_addr, 8)
        self.registers["rsp"] = new_rsp

        self.PC = target_addr
        

    def execute_ret(self):
        rsp_value = self.registers["rsp"]
        ret_addr = self.read_word(rsp_value, 8)

        new_rsp = (rsp_value + 8) & 0xFFFFFFFFFFFFFFFF
        self.registers["rsp"] = new_rsp

        self.PC = ret_addr

    def execute_pushq(self):
        reg_byte = self.read_byte(self.PC + 1)
        rA = self.get_register((reg_byte >> 4) & 0xf)  
        value = self.registers[rA]
        rsp_value = self.registers["rsp"]

        new_rsp = (rsp_value - 8) & 0xFFFFFFFFFFFFFFFF
        self.write_word(new_rsp, value, 8)
        self.registers["rsp"] = new_rsp

        self.PC += 2

    def execute_popq(self):
        reg_byte = self.read_byte(self.PC + 1)
        rA = self.get_register((reg_byte >> 4) & 0xf)  

        rsp_value = self.registers["rsp"]
        value = self.read_word(rsp_value, 8)
        new_rsp = (rsp_value + 8) & 0xFFFFFFFFFFFFFFFF
        self.registers[rA] = value
        self.registers["rsp"] = new_rsp

        self.PC += 2

    def to_signed(self, value):
        """将64位无符号整数转换为有符号整数"""
        if value & 0x8000000000000000:
            return value - 0x10000000000000000
        return value     

    def save_states(self):
        # 检查状态是否与上一次相同，避免保存重复状态
        current_state = {
            "PC": self.PC,
            "STAT": self.stat,
            "ZF": self.ZF,
            "SF": self.SF,
            "OF": self.OF,
            "REG": tuple(self.registers.values())
        }
        
        # 简单比较，如果状态相同则跳过保存
        if self.last_state == current_state:
            return
            
        self.last_state = current_state
        
        #符号码
        CC = {
            "OF": self.OF,
            "SF": self.SF,
            "ZF": self.ZF
        }
        
        # 优化内存状态保存：只记录非零内存块
        mem_state = {}
        
        # 获取所有已使用的内存地址
        memory_addresses = list(self.memory.keys())
        if memory_addresses:
            # 使用集合来记录已处理的块，避免重复处理
            processed_blocks = set()
            
            for addr in memory_addresses:
                block_addr = addr - (addr % 8)  # 对齐到8字节边界
                
                if block_addr in processed_blocks:
                    continue
                    
                processed_blocks.add(block_addr)
                
                # 读取8字节值
                value = 0
                has_data = False
                
                for i in range(8):
                    byte_addr = block_addr + i
                    byte_val = self.memory.get(byte_addr, 0)
                    if byte_val != 0:
                        has_data = True
                    value |= (byte_val << (i * 8))
                
                if has_data:
                    # 转换为有符号表示
                    signed_value = self.to_signed(value)
                    # 将内存地址也转换为有符号表示
                    signed_addr = self.to_signed(block_addr)
                    mem_state[str(signed_addr)] = signed_value
        
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

    def run(self, program_input):
        #读文件
        instructions = self.parse_yo_file(program_input)
        
        if not instructions:
            # 如果没有有效指令，保存初始状态后返回
            self.save_states()
            return self.states
        
        # 设置初始PC为第一条指令的地址
        if instructions:
            self.PC = instructions[0]['address']
        
        # 保存初始状态
        self.save_states()
        
        # 执行循环
        while self.stat == 1:  # 正常执行
            # 检查步数限制
            self.step_count += 1
            if self.step_count > self.max_steps:
                self.stat = 4  # 超时状态
                self.save_states()
                break
                
            # 解码并执行指令
            old_pc = self.PC
            self.fetch()
            
            # 保存执行后状态（每条指令执行后保存）
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
    json.dump(states_history, sys.stdout, indent=4)

if __name__ == "__main__":
    main()