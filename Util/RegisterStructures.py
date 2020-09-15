from envi.archs.amd64 import *

class RegisterStructures:

    @staticmethod
    def get_x64_registers_list():
        return ['rax','rbx','rcx','rdx','rsi','rdi','rsp','rbp','rip','r8','r9','r10','r11','r12','r13','r14','r15']

    @staticmethod
    def get_x86_registers_list():
        return ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp', 'eip']


    @staticmethod
    def get_x64_register_string_constant_map():
        return {'rax': REG_RAX, 'rbx': REG_RBX, 'rcx': REG_RCX, 'rdx': REG_RDX, 'rsi': REG_RSI, 'rdi': REG_RDI, 'rsp': REG_RSP, 'rbp': REG_RBP, 'rip': REG_RIP, 'r8': REG_R8, 'r9': REG_R9, 'r10': REG_R10, 'r11': REG_R11, 'r12': REG_R12, 'r13': REG_R13, 'r14': REG_R14, 'r15': REG_R15}

    @staticmethod
    def get_x86_register_string_constant_map():
        return {'rax': REG_EAX, 'rbx': REG_EBX, 'rcx': REG_ECX, 'rdx': REG_EDX, 'rsi': REG_ESI, 'rdi': REG_EDI, 'rsp': REG_ESP, 'rbp': REG_EBP, 'rip': REG_EIP}
