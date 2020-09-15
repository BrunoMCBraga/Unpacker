import random
import threading
import time
import os
import re
import platform

import vtrace
from vtrace.tools import win32stealth
from vtrace.platforms import win32

import PE

from envi.archs.amd64 import *
from envi.archs.i386 import *
from envi import memory

from Util.WindowsConstants import WindowsConstants
from Util.RegisterStructures import RegisterStructures

from Notifiers.CustomNotifier import CustomNotifier

from BinaryUtils.x86Checker import x86Checker

MAIN_BINARY_TAG = '[MAIN BINARY]'
MAIN_BINARY_FUNCTION_TAG = '[FUNCTION WITHIN MAIN BINARY]'
UNKNOWN_LIBRARY_TAG = '[UNKNOWN LIBRARY]'
UNKNOWN_FUNCTION_TAG = '[UNKNOWN FUNCTION]'
CALL_OR_JUMP_MNEMONIC = '[CALL_OR_JUMP]'
STRINGS_SAVE_DELTA = 120.0
MAX_ITERATIONS_BEFORE_STRINGS_DUMP = 200
MAX_ITERATIONS_BEFORE_STRINGS_DUMP_TURBO = 1000
MAX_TLS_FUNCTIONS = 5
NUMBER_OF_INSTRUCTIONS_TO_DISASSEMBLE_AHEAD = 200
INSTRUCTION_MAXIMUM_LENGTH = 8
CALL_COUNT_THRESHOLD = 10
CONDITIONAL_JUMP_THRESHOLD = 10


class VivisectWindowsEngine:


    def save_execution_strings(self):
        print('Engines->VivisectWindowsEngine->save_execution_strings: saving strings.')
        self.strings_output_writter.write_strings_list_to_file(self.execution_strings_set)


    def __init__(self, file_path, commandline_args, strings_output_writter, program_output_writter, starting_address):
        self.file_path = file_path
        self.args = commandline_args
        self.execution_strings_set = set()
        self.address_cache = {}
        self.allocated_pages = {}
        self.tracked_threads = {}
        self.call_counts = {}
        self.conditional_jump_counts = {}

        machine = platform.machine()

        if machine == 'i386':
            print('Engines->VivisectWindowsEngine->__init__: 32bit architecture detected.')
            self.platform_bits = 32
        else:
            print('Engines->VivisectWindowsEngine->__init__: 64bit architecture detected.')
            self.platform_bits = 64


        pe = PE.peFromFileName(file_path)
        machine = pe.IMAGE_NT_HEADERS.FileHeader.Machine
        arch_name = PE.machine_names.get(machine)

        if arch_name == 'amd64':
            print('Engines->VivisectWindowsEngine->__init__: amd64 binary detected.')
            self.bin_bits = 64
        elif arch_name == 'i386':
            print('Engines->VivisectWindowsEngine->__init__: i386 binary detected.')
            self.bin_bits = 32
        else:
            raise NotImplementedError('Engines->VivisectWindowsEngine->__init__: unknown architecture.')

        self.trace = vtrace.getTrace()

        #The timers are not working well for some reason. i am not sure if it is because the main program keeps running and the timer gets no priority. The generated strings file is all messed up :/
        #timer = threading.Timer(STRINGS_SAVE_DELTA, self.save_execution_strings)
        #self.timer = timer
        #timer.start()

        self.strings_output_writter = strings_output_writter
        self.program_output_writter = program_output_writter

        self.mutex = threading.Lock()

        # The notifier class we want to register
        notif = CustomNotifier(self)

        # Tell our vtrace object that we want to capture all events with CustomNotifier
        self.trace.registerNotifier(vtrace.NOTIFY_LOAD_LIBRARY, notif)
        self.notif = notif
        self.starting_address = starting_address



    def clean_up(self):
        # Deregister our notifier
        #self.trace.deregisterNotifier(vtrace.NOTIFY_LOAD_LIBRARY, self.notif)
        pass


    def enable_anti_anti_debugging(self):
        print('Engines->VivisectWindowsEngine->enable_anti_anti_debugging: Enabling Anti-Debugging.')
        #win32stealth.enableAllStealth(self.trace)
        win32stealth.stealthify(self.trace, 'Peb')
        win32stealth.stealthify(self.trace, 'CheckRemoteDebuggerPresent')
        win32stealth.stealthify(self.trace, 'GetTickCount')
        win32stealth.stealthify(self.trace, 'OutputDebugString')
        win32stealth.stealthify(self.trace, 'ZwClose')
        win32stealth.stealthify(self.trace, 'ZwSetInformationThread')
        win32stealth.stealthify(self.trace, 'ZwQueryInformationProcess')
        win32stealth.stealthify(self.trace, 'ZwQueryInformationProcess')


    def disable_anti_anti_debugging(self):
        print('Engines->VivisectWindowsEngine->disable_anti_anti_debugging: Enabling Anti-Debugging.')
        win32stealth.unstealthify(self.trace, 'Peb')
        win32stealth.unstealthify(self.trace, 'CheckRemoteDebuggerPresent')
        win32stealth.unstealthify(self.trace, 'GetTickCount')
        win32stealth.unstealthify(self.trace, 'OutputDebugString')
        win32stealth.unstealthify(self.trace, 'ZwClose')
        win32stealth.unstealthify(self.trace, 'ZwSetInformationThread')
        win32stealth.unstealthify(self.trace, 'ZwQueryInformationProcess')
        win32stealth.unstealthify(self.trace, 'ZwQueryInformationProcess')


    def update_memory_map(self, va):

        memory_map_meta = self.trace.getMemoryMap(va)
        self.allocated_pages[va] = memory_map_meta


    def get_allocated_pages(self):
        return self.allocated_pages


    def get_execution_strings_set(self):
        return self.execution_strings_set


    #Address Cache
    def get_address_cache(self):
        return self.address_cache


    def get_address_size_for_memory(self, va):
        if va in self.allocated_pages:
            return self.allocated_pages[va][1]
        else:
            return 0x0


    def get_loaded_module_exports(self, loaded_library):

        libs = self.trace.getMeta("LibraryPaths")
        base = None
        pe = None

        address_cache = {}

        for k, v in libs.iteritems():
            base = k
            library_path = v

            if loaded_library in library_path:

                if base is None:
                    pe = PE.peFromFileName(loaded_library)
                    base = pe.IMAGE_NT_HEADERS.OptionalHeader.ImageBase
                else:
                    pe = PE.peFromMemoryObject(self.trace, base)

                for export in pe.exports:
                    address_cache[base + export[0]] = (loaded_library, export[2])

        return address_cache

    def update_cache(self, loaded_library):

        module_exports_dict = self.get_loaded_module_exports(loaded_library)
        self.address_cache.update(module_exports_dict)


    # check if memory is readable
    def read_memory(self, memory_address, length):
        bytes = bytearray()

        try:
            bytes = bytearray([ord(b) for b in self.trace.readMemory(memory_address, length)])
        except Exception as e:
            # raise Exception('Engines->read_memory: ' + str(e)) For now i am commenting this and ignoring access violations. Need to check them later..
            #print "ERROR: ", sys.exc_info()[1]
            #print("Util->VivisectEngineGenericUtils->read_memory: " + str(e))
            pass
        return bytes

    # check if memory is readable??? check if i need to do ord for every read value. it seems a string is returned??
    def read_memory_formatted(self, memory_address, format):
        bytes = bytearray()

        try:
            bytes = self.trace.readMemoryFormat(memory_address, format)  # RIP on stack
        except Exception as e:
            # raise Exception('Engines->read_memory: ' + str(e)) For now i am commenting this and ignoring access violations. Need to check them later..
            # print "ERROR: ", sys.exc_info()[1]
            #print("Util->VivisectEngineGenericUtils->read_memory: " + str(e))
            pass
        return bytes

    def print_loaded_libs(self):
        libs = self.trace.getMeta("LibraryPaths")
        for base, library in libs.iteritems():
            '{}:{}'.format(str(base), library)



    def disasm_at_va(self, va, number_of_instructions):

        result = None

        disassembler = None

        decompilation_result = []

        bytes = self.trace.readMemory(va, number_of_instructions * INSTRUCTION_MAXIMUM_LENGTH)

        if self.platform_bits == 32:
            disassembler = i386Disasm()
        elif self.platform_bits == 64 and self.bin_bits == 32:
            disassembler = i386Disasm()
        else:
            disassembler = Amd64Disasm()

        i = 0
        rip = va
        number_of_dis_instructions = 0

        while number_of_dis_instructions < number_of_instructions:
            try:
                opcode = disassembler.disasm(bytes, i, rip)
                decompilation_result.append([hex(rip), opcode])
                i += opcode.size
                rip += opcode.size
                number_of_dis_instructions += 1
            except:
                if self.platform_bits == 32:
                    disassembler = Amd64Disasm()
                elif self.platform_bits == 64 and self.bin_bits == 32:
                    disassembler = Amd64Disasm()
                else:
                    disassembler = i386Disasm()
                i += 1
                rip += 1
                number_of_dis_instructions += 1
                continue
                #we stop as soon as it fails. This can be a problem if a sample uses a mix of 32 and 64.
                '''
                if self.platform_bits == 32:
                    disassembler = Amd64Disasm()
                else:
                    disassembler = i386Disasm()
                '''
        return decompilation_result

    # Will decode shellcode in a linear manner
    # shellcode must be in the format '\x90\x90\xCC\xCC'
    # for the code to function properly
    # The filter is used to choose which instructions are saved
    #This function is supposed to call some operation until a condition is met. I will not call the function above because i don't want to disassemvle everything to avoid performance penalties
    # Operation should receive EIP, INSTRUCTION_BYTES and do something with it. If the operation fails and wants more bytes, it should return False so that it can be called again with the next instruction
    def disasm_at_va_and_perform_operation(self, va, operation):

        print('Engines->VivisectWindowsEngine->disasm_at_va_and_perform_operation.')

        result = None

        disassembler = None

        #decompilation_result = []

        bytes = self.trace.readMemory(va, NUMBER_OF_INSTRUCTIONS_TO_DISASSEMBLE_AHEAD * INSTRUCTION_MAXIMUM_LENGTH)

        if self.platform_bits == 32:
            disassembler = i386Disasm()
        elif self.platform_bits == 64 and self.bin_bits == 32:
            disassembler = i386Disasm()
        else:
            disassembler = Amd64Disasm()

        i = 0
        rip = va

        ###PROBLEM HERE: current instruction. should i be skipped or not???? in case i need to step over, i have no way of knowing when the operation is being called to current eip or next...

        #print('Current VA:' + hex(va))
        while True:
            try:

                #if we reach the end of the byte array we update...
                if i >= (len(bytes) - 1):
                    print("Reading more================================================================================================================================???")
                    bytes = self.trace.readMemory(rip, NUMBER_OF_INSTRUCTIONS_TO_DISASSEMBLE_AHEAD * INSTRUCTION_MAXIMUM_LENGTH)
                    i = 0

                disassembled_bytes = disassembler.disasm(bytes, i, rip)
                operation_result = operation(rip, [ord(b) for b in bytes[i:i+disassembled_bytes.size:]])

                ##For some idiotic reason, the readMemory returns an array of strings and the disasm expects that :O
                #instruction_bytes = [ord(b) for b in bytes[i:i+disassembled_bytes.size:]]
                #print("Index:" + str(i))
                #print("Size:" + str(len(instruction_bytes)))
                #print([hex(b) for b in instruction_bytes])

                #match_instruction_regex = re.match(instruction_regex, instruction_string)
                #print('EIP:{} Instruction:{} Opcode Size:{}'.format(hex(rip), str(disassembled_bytes), disassembled_bytes.size))

                if operation_result:
                   #decompilation_result.append([rip, opcode])
                   #print('Match VA:' + hex(rip))
                   #operation(rip)
                   return True
                else:
                    i += disassembled_bytes.size
                    rip += disassembled_bytes.size
            except Exception as e:
                print(e)
                if self.platform_bits == 32:
                    disassembler = Amd64Disasm()
                elif self.platform_bits == 64 and self.bin_bits == 32:
                    disassembler = Amd64Disasm()
                else:
                    disassembler = i386Disasm()
                i += 1
                rip += 1
                continue
                #we stop as soon as it fails. This can be a problem if a sample uses a mix of 32 and 64.


        #return decompilation_result



    #Maybe there is a vivisect function for this?
    def get_address_range_for_binary_in_memory(self, file_path):

        libs = self.trace.getMeta("LibraryPaths")
        base = None
        pe = None

        for k, v in libs.iteritems():
            base = k
            library_path = v
         
            if base is None:
                pe = PE.peFromFileName(library_path)
                base = pe.IMAGE_NT_HEADERS.OptionalHeader.ImageBase
            else:
                pe = PE.peFromMemoryObject(self.trace, base)

            if file_path in library_path:
                last_section_header = pe.sections[-1]
                last_section_rva = last_section_header.VirtualAddress
                last_section_virtual_size = last_section_header.VirtualSize
                return (base, base + last_section_rva + last_section_virtual_size)

        return ()

    def is_ip_within_libs(self, ip):
        libs = self.trace.getMeta("LibraryPaths")
        base = None
        pe = None

        # print(hex(eip))
        # This getSymByAddr does not seem to work :////
        # symbol_name = self.trace.getSymByAddr(eip, exact=False)
        module, function = self.address_to_module_and_function_name(ip)
        # What if it is one of the first functions being called before the binary???? i am jumping to Entrypoint....i check if there is a symbol around...Cache not being used at this point
        if ip in self.get_address_cache():
            return True

        if module == MAIN_BINARY_TAG:
            return False

        # We keep running within the main binary
        # main_bin_range = self.get_address_range_for_binary_in_memory(self.file_path)
        # if (eip > main_bin_range[0]) and (eip < main_bin_range[1]):
        #    return False

        for k, v in libs.iteritems():
            base = k
            library_path = v

            # We ignore the current binary. We are looking only for loaded libraries.
            if self.file_path in library_path:
                continue

            # Basically i jump out of any loaded dll...What if there is shellcode there???? i could in theory check if there are any symbols for this function to make sure there is no shellcode.
            bin_range = self.get_address_range_for_binary_in_memory(library_path)
            # Outside binary.... i am not accounting for shellcode in allocated regions on libraries or malicious dlls....

            if (ip >= bin_range[0]) and (ip <= bin_range[1]):
                return True

        return False


    def update_tracked_threads(self, thread_id, start_address):

        #If the entrypoint for the thread is outside the loaded libraries, i assume it is within the malware or some allocated space so i track it
        if not self.is_ip_within_libs(start_address):
            self.tracked_threads[thread_id] = self.trace.getThreads()[thread_id]

    '''
    Stepping Out
    '''
    # The idea here is that if the current EIP Falls within some loaded lib that is not the malware itself, we stepout.
    # This is not great if the malware decides to load an auxiliary and malicious module. We can run some regex to make sure the loaded dll is on a whitelisted folder.
    def can_stepout(self):

        eip = None
        if self.platform_bits == 32:
            eip = self.trace.getRegister(REG_EIP)
        else:
            eip = self.trace.getRegister(REG_RIP)

        return self.is_ip_within_libs(eip)


    def is_on_32_bit_instructions(self):

        result = None

        eip = None
        if self.platform_bits == 32:
            eip = self.trace.getRegister(REG_EIP)
        else:
            eip = self.trace.getRegister(REG_RIP)

        disassembler = i386Disasm()

        # Temporary solution for the case where the code transitions to 32 bits from 64 and vice-versa. Need to look at Vivisect to see if there is a method to find the type of disassewmbler...

        try:
            bytes = self.trace.readMemory(va, 30)
            disassembler.convert_bytes_to_instructions(bytes, 0, va)
        except Exception as e:
            return False


        return True


    ##This is buggy. Must take into account first instructions where addresses are invalid....Seems to happen with 32bit only....
    def step_out(self):

        esp = None

        if self.platform_bits == 32:
            esp = self.trace.getRegister(REG_ESP)
        else:
            esp = self.trace.getRegister(REG_RSP)

        esp = self.trace.getRegister(REG_RSP)
        if esp == 0:
            return


        pointer_format_character = 'P'


        '''
        Still trying to wrap my head around this. When i use vivisect to disassemble instructions on a cmd32 binary i see x64 registers being used. Ida does not show those. 
        I belive the 64 registers are used in full and pushed on stack even if the binary is x86?
        '''
        if self.platform_bits == 64 and self.bin_bits == 32:
            #if self.is_on_32_bit_instructions():
            pointer_format_character = 'I' # we are in 32 bits instructions so the pointers are 32bit length

        stack = self.trace.getStackCounter()
        fmt = '<' + pointer_format_character
        args = self.trace.readMemoryFormat(stack, fmt) # RIP on stack
        #print([hex(arg) for arg in args])
        ret_ip = args[0]

        #print([hex(arg) for arg in args])

        ip_memory_map = self.trace.getMemoryMap(ret_ip)


        '''
        We make sure that the Ret IP is not null
        We make sure there is a memory mao
        We make sure it is read and exec (has code)
        '''

        #i am using this loop to make sure it jumps out when exceptions are hit. the problem is that sometimes the routine for the exception is too bog.
        while True:

            if ret_ip != 0x0 and ip_memory_map is not None and (ip_memory_map[2] & memory.MM_READ_EXEC):
                # Set breakpoint at address. This not be good because i may miss TLS
                bp = vtrace.Breakpoint(ret_ip)
                #self.disable_anti_anti_debugging()
                self.trace.addBreakpoint(bp)
                self.trace.run()
                self.trace.removeBreakpoint(bp.getId())
                #self.enable_anti_anti_debugging()

                eip = None

                if self.platform_bits == 32:
                    eip = self.trace.getRegister(REG_EIP)
                else:
                    eip = self.trace.getRegister(REG_RIP)


                if eip == ret_ip:
                    break

            else:
                print("Failed to step out!!!!")
                break


    '''
    Memory Sweeping
    
    '''

    # Check if free and readable...It seems the string requestedPrivileges from the manifest is not present... With thorough, it scans the whole mapping of pages instead of using the rudimentary cache built with function hooks.
    '''
    Vivisect offers a means to search memory as so:
    unicode_search_result = self.trace.searchMemory('([\x01-\x7E]\x00)+\x00\x00', regex=True)
    
    However, the only thing they return is offsets for the matches without size so i am left with the task of reading a seemingly guessable amount of bytes from memory and then iterate and cut. I am implementing this froms scratch.
    
    '''
    def extract_strings_from_memory(self, thorough):

        chosen_memory_map = self.allocated_pages.values()

        if thorough:
            chosen_memory_map = self.trace.getMemoryMaps()

        if chosen_memory_map == None:
            print("Engines->VivisectWindowsEngine->extract_strings_from_memory: memory maps is None.")

        for address, size, perm, fname in chosen_memory_map:

            '''
            In order to avoid scanning loaded dlls (what if the malware is a dll??), we continue to the next map if the name is not empty (there is a path and likely for a windows legitimate dll) and the address is not part of the main binary. We are left with the binary itself
            and allocated pages. 

            It seems that if i put this check here i miss a shitload of strings ....
            '''
            if fname != self.file_path and fname != '':
                continue

            # for address, size, perm, _ in self.trace.getMemoryMaps():
            # for address, size in self.get_allocated_pages().iteritems():

            if not perm & memory.MM_READ:
                # print("Engines->VivisectWindowsEngine->extract_strings_from_memory: address {} not readable.".format(hex(address)))
                continue

            memory_bytes = self.read_memory(address, size)

            # it seems that some memory addresses, while having Read Permissions still cause exceptions on read and return None :/ Error 299. People report it has to do with PAGE_GUARD
            '''
            The PAGE_GUARD flag is particularly interesting here, as it works as a one-time PAGE_NOACCESS marker; i.e. after setting the modifier on a single memory page, 
            the first operation against the page results in triggering a STATUS_GUARD_PAGE_VIOLATION exception and automatically restoring its original access rights.

            Tried the code below. Still not able to read.

            page_guard_set = True if perm & win32.PAGE_GUARD else False

            if page_guard_set:
                self.trace.protectMemory(address, size, perm & 0xFEFF)


            self.trace.protectMemory(address, size, perm)
            Based on checks on perms, it seems it is not a PAGE_GUARD problem.
            '''

            page_guard_set = True if (perm & win32.PAGE_GUARD) else False

            if memory_bytes == None:
                # print("Engines->VivisectWindowsEngine->extract_strings_from_memory address->read_memory: address {} read returned None.".format(hex(address)))
                if page_guard_set:
                    memory_bytes = self.read_memory(address, size)
                    if memory_bytes == None:
                        # print("Engines->VivisectWindowsEngine->extract_strings_from_memory address->read_memory: address {} read returned None (second attempt).".format(hex(address)))
                        continue
                else:
                    continue

            # print("Engines->VivisectWindowsEngine->extract_strings_from_memory address: reading address {}.".format(hex(address)))

            memory_bytes_copy = memory_bytes

            unicode_offsets = {}

            '''
            test_regex = re.compile('.*requestedPrivileges.*')
            m = re.search(test_regex, memory_bytes)
            if m is not None:
                print('MATCHED .*requestedPrivileges.*')
            '''

            # unicode_regex = re.compile('((\x08|[\x09-\x0A]|\x0D|[\x20-\x7E])\x00)+\x00\x00')
            # ascii_regex = re.compile('(\x08|[\x09-\x0A]|\x0D|[\x20-\x7E]){2,}\x00')

            # UNICODE
            #I am removing the ending zeros because there may be strings with trash. i want to make sure the sequences are of readable characters
            unicode_regex = re.compile('([\x20-\x7E]\x00)+')
            unicode_matches = re.finditer(unicode_regex, memory_bytes)

            # We keep slicing the array so we need to keep track of the distance from the beginning so we can know exactly where the unicode matches took place.
            offset_from_beginning = 0
            for unicode_match in unicode_matches:
                # print("MATCH-UNICODE:" + m.group(0) + " Index:" + str(offset_from_beginning + m.start(0)))
                #self.mutex.acquire()
                self.execution_strings_set.add('{}:{}'.format(hex(address + unicode_match.start(0)), unicode_match.group(0)))
                #self.mutex.release()

            # ASCII. Nothing matching here????? Move this to Utilclass MemoryDataInterpreter???
            ascii_regex = re.compile('[\x20-\x7E]{2,}')
            # I am testing another regex here. I belive that if i force the strings to be at least two characters, i will not fall into the problem of hitting on Unicode strings and so i dont need to keep track of their location.  I may actually be able to leverage
            # Vivisect memory search with regexes///
            # ascii_regex = re.compile('[\x01-\x7E]{2,}\x00')
            ascii_matches = re.finditer(ascii_regex, memory_bytes)
            offset_from_beginning = 0

            for ascii_match in ascii_matches:
                # print("MATCH-ASCII:" + m.group(0) + " Index:" + str(offset_from_beginning + m.start(0)))
                #self.mutex.acquire()
                self.execution_strings_set.add('{}:{}'.format(hex(address + ascii_match.start(0)), ascii_match.group(0)))
                #self.mutex.release()



    def get_function_arguments(self, argument_count):

        arguments_list = []

        remaining_arguments = argument_count
        eip_size = 0
        if self.platform_bits == 32:
            eip_size = 1
        else:
            eip_size = 1

        #here i have to use the bits for the binary....There is a problem here though. What happens when there are transitions from 64 to 32. There is also a problem with calling conventions??????
        #Wow64. Problem with transitions????
        if self.platform_bits == 64 and self.bin_bits == 64:

            register_arguments = [self.trace.getRegister(REG_RCX),
                                  self.trace.getRegister(REG_RDX),
                                  self.trace.getRegister(REG_R8),
                                  self.trace.getRegister(REG_R9)]

            number_of_registers_used = 0
            for i in range(0, argument_count):
                if i < len(register_arguments):
                    arguments_list.insert(i, register_arguments[i])
                    number_of_registers_used += 1

            remaining_arguments = argument_count - number_of_registers_used

        pointer_format_character = 'P'

        '''
        Still trying to wrap my head around this. When i use vivisect to disassemble instructions on a cmd32 binary i see x64 registers being used. Ida does not show those. I belive the 64 registers are used in full and pushed on stack even if the binary is x86?
        '''

        if self.platform_bits == 64 and self.bin_bits == 32:
            # if self.is_on_32_bit_instructions():
            pointer_format_character = 'I'  # we are in 32 bits instructions so the pointers are 32bit length

        #I think it is better if i just run 32 bits malware on 32 bits machine. I am having a shitload of issues with Wow64. I have to take into account that sometimes the code transitions from 64 to 32 and for each case i must pay attention when disassembling and even reading stack arguments.
        if remaining_arguments > 0:
            stack = self.trace.getStackCounter()
            fmt = '<' + (pointer_format_character + pointer_format_character * remaining_arguments)
            args = self.trace.readMemoryFormat(stack, fmt)[1::]#RIP on stack
            #print([hex(arg) for arg in args])
            arguments_list.extend(args)



        #print([hex(x) for x in arguments_list])
        return arguments_list



    def get_oep(self, file_path):
        base = None

        libs = self.trace.getMeta("LibraryPaths")
        for k, v in libs.iteritems():
            if file_path in v:
                base = k

        if base is None:
            p = PE.peFromFileName(file_path)
            base = p.IMAGE_NT_HEADERS.OptionalHeader.ImageBase
        else:
            p = PE.peFromMemoryObject(self.trace, base)

        ep = p.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint
        #print('Base:' + hex(base) + ' EntryPoint:' + hex(ep))# For some reason, it is not printing correctly.... For system32 cmd.exe, the entrypoint is 0x90b4 while the one shown by PE viewer is 0x829a
        oep = base + ep

        return oep



    '''
    trace.getSymByAddr
    Can i optimize this? Can i get a module based on VA?
    '''
    def address_to_module_and_function_name(self, va):

        libs = self.trace.getMeta("LibraryPaths")
        base = None
        pe = None

        if va in self.address_cache:
            return self.address_cache[va]

        for k, v in libs.iteritems():
            base = k
            library_path_temp = v
            library_path_out = UNKNOWN_LIBRARY_TAG

            if base is None:
                pe = PE.peFromFileName(self.file_path)
                base = pe.IMAGE_NT_HEADERS.OptionalHeader.ImageBase
            else:
                pe = PE.peFromMemoryObject(self.trace, base)

            if self.file_path in library_path_temp:
                bin_range = self.get_address_range_for_binary_in_memory(self.file_path)
                #print("Main Binary Base:" + str(hex(bin_range[0])))
                if (va >= bin_range[0]) and (va <= bin_range[1]):
                    function_name = self.trace.getSymByAddr(va, exact=False)

                    if function_name is not None:
                        return (MAIN_BINARY_TAG, function_name)
                    else:
                        return (MAIN_BINARY_TAG, MAIN_BINARY_FUNCTION_TAG)

            #This is a bit silly...i am iterating and then i just use getSymByAddr. i think this is because i need the library...
            bin_range = self.get_address_range_for_binary_in_memory(library_path_temp)
            if (va >= bin_range[0]) and (va <= bin_range[1]):
                library_path_out = library_path_temp
                function_name = self.trace.getSymByAddr(va, exact=False)
                if function_name is not None:
                    return (library_path_out, function_name)
                else:
                    for export in pe.exports:
                        if va == base + export[0]:
                            return (library_path_out, export[2])

                '''
                for export in pe.exports:
                    if va == base + export[0]:
                        return (library_path, export[2])
                '''

        return (library_path_out, UNKNOWN_FUNCTION_TAG)


    def set_bp_and_run(self, eip):

        print('Engines->VivisectWindowsEngine->set_bp_and_run: Jumping to:' + str(hex(eip)))

        self.tracked_threads[self.trace.getCurrentThread()] = eip

        while True:
            # Set breakpoint at address. This not be good because i may miss TLS
            bp = vtrace.Breakpoint(eip)
            #self.disable_anti_anti_debugging()
            self.trace.addBreakpoint(bp)
            self.trace.run()
            self.trace.removeBreakpoint(bp.getId())
            #self.enable_anti_anti_debugging()

            new_eip = None

            if self.platform_bits == 32:
                new_eip = self.trace.getRegister(REG_EIP)
            else:
                new_eip = self.trace.getRegister(REG_RIP)


            if new_eip == eip:
                break


    def find_next_valid_instruction_and_run_to_it(self, eip, instructions_bytes):

        is_positive_conditional_jmp_two_bytes = x86Checker.is_positive_conditional_jmp_two_bytes(instructions_bytes)
        is_negative_conditional_jmp_two_bytes = x86Checker.is_negative_conditional_jmp_two_bytes(instructions_bytes)
        is_jmp_two_bytes = x86Checker.is_jmp_two_bytes(instructions_bytes)
        is_jmp_one_byte = x86Checker.is_jmp_one_byte(instructions_bytes)
        is_positive_jmp_one_byte = x86Checker.is_positive_jmp_one_byte(instructions_bytes)
        is_negative_jmp_one_byte = x86Checker.is_negative_jmp_one_byte(instructions_bytes)

        is_call_two_bytes = x86Checker.is_call_two_bytes(instructions_bytes)
        is_call_one_byte = x86Checker.is_call_one_byte(instructions_bytes)

        is_rep = x86Checker.is_rep(instructions_bytes)
        is_loop = x86Checker.is_loop(instructions_bytes)
        is_ret = x86Checker.is_ret(instructions_bytes)

        if is_positive_conditional_jmp_two_bytes or is_negative_conditional_jmp_two_bytes or is_jmp_two_bytes or is_jmp_one_byte or is_positive_jmp_one_byte or is_negative_jmp_one_byte or is_call_two_bytes or is_call_one_byte or is_rep or is_loop or is_ret:
            #instructions_string = str(instructions_bytes)
            #print('Match:{}:{}'.format(hex(eip), instructions_string))
            self.set_bp_and_run(eip)
            return True

        return False




    def skip_rep(self):

        eip = None
        if self.platform_bits == 32:
            eip = self.trace.getRegister(REG_EIP)
        else:
            eip = self.trace.getRegister(REG_RIP)

        next_instruction_eip = self.disasm_at_va(eip, 10)[1][0]

        self.set_bp_and_run(long(next_instruction_eip.rstrip('L'), 16))


    def jump_over_instruction_with_bp(self, eip):

        instructions_list = self.disasm_at_va(eip, 2)
        next_eip = instructions_list[1][0]
        self.set_bp_and_run(long(next_eip.rstrip('L'), 16))


    def get_tls_callbacks(self):

        tls_callbacks_return = []

        pe = PE.peFromFileName(self.file_path)
        tls_directory_rva = pe.getDataDirectory(PE.IMAGE_DIRECTORY_ENTRY_TLS).VirtualAddress

        main_bin_address_range = self.get_address_range_for_binary_in_memory(self.file_path)
        print(main_bin_address_range)

        tls_directory_rva += main_bin_address_range[0]

        pointer_format_character = 'P'

        '''
        Still trying to wrap my head around this. When i use vivisect to disassemble instructions on a cmd32 binary i see x64 registers being used. Ida does not show those. I belive the 64 registers are used in full and pushed on stack even if the binary is x86?
        May not be necessary
        '''

        if self.platform_bits == 64 and self.bin_bits == 32:
            # if self.is_on_32_bit_instructions():
            pointer_format_character = 'I'  # we are in 32 bits instructions so the pointers are 32bit length

        tls_directory_dwords = self.read_memory_formatted(tls_directory_rva, '<'+pointer_format_character*6)
        address_of_callbacks = tls_directory_dwords[3]

        tls_callbacks_offsets = self.read_memory_formatted(address_of_callbacks, '<'+pointer_format_character*MAX_TLS_FUNCTIONS)

        for tls_callbacks_offset in tls_callbacks_offsets:
            if tls_callbacks_offset != 0:
                tls_callbacks_return.append(tls_callbacks_offset)

        return tls_callbacks_return


    def go_back_to_tracked_thread_if_current_not_tracked(self):

        #chosen_thread_index = random.randint(0,len(self.tracked_threads))
        #print('Engines->VivisectWindowsEngine->go_back_to_tracked_thread_if_current_not_tracked.')

        bps_list = []

        eip_constant = None

        if self.platform_bits == 32:
            eip_constant = REG_EIP
        else:
            eip_constant = REG_RIP

        if self.trace.getCurrentThread() not in self.tracked_threads:
            for thread_id in self.tracked_threads.keys():
                rip_value = self.trace.getRegisterContext(thread_id).getRegister(eip_constant)
                print("Thread RIP:" + str(hex(rip_value)))
                bp = vtrace.Breakpoint(rip_value)
                self.trace.addBreakpoint(bp)
                bps_list.append(bp)

            # we run until we are within monitored thread
            while self.trace.getCurrentThread() not in self.tracked_threads:
                print("Running until next thread")
                self.trace.run()  # we just run until a BP is hit. If i set BPs before any context switches, it should stop there.

            #We remove bps to avoid malware that detects them
            for bp in bps_list:
                self.trace.removeBreakpoint(bp.getId())

    #TODO: Adjust for x86
    '''
    Some optimizations: Assume that the functions are not broken and are sequential. This means i can do two things:
    1. I can scan for next calls and jump there directly and jump over conditional branching (problems with shellcode....)
    2. USE hardware BPs!!!!!!!!!!!!
    '''
    def run_through(self, run_through_instructions_outside_main_binary, thorough_string_scan, track_library_calls, track_library_call_arguments, track_library_call_returns, optimistic_mode):

        self.trace.execute(self.file_path + ' ' + self.args)

        top_level_functions = self.get_tls_callbacks()

        # In order to speedup the execution
        oep = self.get_oep(self.file_path)
        top_level_functions.append(oep)
        top_level_functions_index = 0

        #print('Before EIP:' + hex(self.trace.getRegister(REG_RIP)))
        # Set breakpoint at address. This not be good because i may miss TLS
        #print('Setting Breakpoint:' + hex(oep))

        main_bin_range = self.get_address_range_for_binary_in_memory(self.file_path)


        self.enable_anti_anti_debugging()

        # I add main thread to list of tracked threads. Not relevant the entry point.

        if self.starting_address == 0x0:
            self.set_bp_and_run(top_level_functions[top_level_functions_index])
            self.update_tracked_threads(self.trace.getMeta("ThreadId"), top_level_functions[top_level_functions_index])
        else:
            #in this case, we clear the top level functions. I have no idea beforehand whether the entrypoint is within TLS or Before the entrypoint.
            self.set_bp_and_run(self.starting_address)
            self.update_tracked_threads(self.trace.getMeta("ThreadId"), self.starting_address)
            top_level_functions = []


        # Here i am making sure i keep track of strings within the binary it
        binary_address_range = self.get_address_range_for_binary_in_memory(self.file_path)
        self.update_memory_map(binary_address_range[0])

        formatted_string = 'Base for binary:{}'.format(hex(main_bin_range[0]))
        print(formatted_string)

        self.program_output_writter.write_string_to_file(formatted_string + os.linesep)
        iteration_counter = 0

        #regex_for_next_valid_instruction = 'call.*|j.*|rep.*|ret.*'


        while True:

            self.go_back_to_tracked_thread_if_current_not_tracked()

            eip = None

            if self.platform_bits == 32:
                eip = self.trace.getRegister(REG_EIP)
            else:
                eip = self.trace.getRegister(REG_RIP)

            # This is bad because assumes no virtualallocs and stuff outside the main binary range. Good for testing purposes.

            formatted_string = 'Current EIP:{}'.format(hex(eip))
            print(formatted_string) #hidding this to avoid too much verbosity
            self.program_output_writter.write_string_to_file(formatted_string + os.linesep)


            saved_eip = eip
            #i read 3 to account for prefixes...
            next_instruction_bytes = self.read_memory(eip, 3)
            #next_instruction_bytes = [ord(h) for h in next_instruction_bytes]

            #if next_instruction_bytes[0] in [0x64, 0x66, 0x67, 0xF3, 0xF0, 0x48, 0x41]:
            #    next_instruction_bytes = next_instruction_bytes[1::]

            #print([hex(h) for h in next_instruction_bytes])

            disassemble_result = self.disasm_at_va(saved_eip, 5)
            #####print("Current Instruction: [{}]{}:{}".format(self.trace.getCurrentThread(), hex(saved_eip), disassemble_result))
            #####print([b for b in next_instruction_bytes])

            # There is also another problem with step out. If i step out on a call to a function within the binary, i miss information...

            called_function = ''
            function_arguments = None

            # Not detecting execution in allocate memory???? Maybe replace this with multiple ranges. I should check that this code is executed when the RIP is outside any legit dlls. That is still a problem for malware that allocates memory on those :/ Go crazy????
            #I am commenting this loop. Checking boundaries is irrelevant since i am assuming i start within the binary with the breakpoint on entrypoint. without that breakpoint this will fail because i will try to stepout.
            #if run_through_instructions_outside_main_binary or (eip >= main_bin_range[0]) and (eip <= main_bin_range[1]):

            # Remove jmp for now. the step outs with jmp are a bit harder because i must check if the jump is to some library function
            # if splitted_instruction_by_space[0] in ['call', 'jmp']:
            #I have seen gs: instructions...?? is this happening with calls????
            #if splitted_instruction_by_space[0] in ['call', 'jmp', 'jo', 'jno', 'js', 'jns', 'je', 'jz', 'jne', 'jnz', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jbe', 'jna', 'ja', 'jnbe', 'jl', 'jnge', 'jge', 'jnl', 'jle', 'jng', 'jg', 'jnle', 'jp', 'jpe', 'jnp', 'jpo', 'jcxz', 'jecxz']:
            #Slashing down on the number of processed instructions to speed up things....for testing purposes..

            # conditional jump near and calls
            '''
            modr = ((next_instruction_bytes[1] >> 3) & 7)

            is_positive_conditional_jmp_two_bytes = True if (next_instruction_bytes[0] == 0x0F and next_instruction_bytes[1] in [0x80, 0x84, 0x88, 0x8A]) else False
            is_negative_conditional_jmp_two_bytes = True if (next_instruction_bytes[0] == 0x0F and next_instruction_bytes[1] in [0x81, 0x82, 0x83, 0x85, 0x86, 0x87, 0x89, 0x89, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F]) else False
            is_jmp_two_bytes = True if next_instruction_bytes[0] == 0xFF and (modr == 4 or modr == 5) else False
            is_jmp_one_byte = True if next_instruction_bytes[0] in [0xE9, 0xEA, 0xEB] else False
            is_positive_jmp_one_byte = True if next_instruction_bytes[0] in [0x70, 0x74, 0x78, 0x7A, 0xE3] else False
            is_negative_jmp_one_byte = True if next_instruction_bytes[0] in [0x71, 0x72, 0x73, 0x75, 0x76, 0x77, 0x79, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F] else False


            is_call_two_bytes = True if (next_instruction_bytes[0] == 0xFF) and (modr == 2 or modr == 3) else False
            is_call_one_byte = True if next_instruction_bytes[0] in [0xE8] else False


            is_rep = True if next_instruction_bytes[0] in [0xF2, 0xF3] else False
            is_loop = True if next_instruction_bytes[0] in [0xE0, 0xE1, 0xE2] else False
            is_ret = True if next_instruction_bytes[0] in [0xC2, 0xC3, 0xCA, 0xCB, 0xCF] else False
            '''

            is_positive_conditional_jmp_two_bytes = x86Checker.is_positive_conditional_jmp_two_bytes(next_instruction_bytes)
            is_negative_conditional_jmp_two_bytes = x86Checker.is_negative_conditional_jmp_two_bytes(next_instruction_bytes)
            is_jmp_two_bytes = x86Checker.is_jmp_two_bytes(next_instruction_bytes)
            is_jmp_one_byte = x86Checker.is_jmp_one_byte(next_instruction_bytes)
            is_positive_jmp_one_byte = x86Checker.is_positive_jmp_one_byte(next_instruction_bytes)
            is_negative_jmp_one_byte = x86Checker.is_negative_jmp_one_byte(next_instruction_bytes)

            is_call_two_bytes = x86Checker.is_call_two_bytes(next_instruction_bytes)
            is_call_one_byte = x86Checker.is_call_one_byte(next_instruction_bytes)

            is_rep = x86Checker.is_rep(next_instruction_bytes)
            is_loop = x86Checker.is_loop(next_instruction_bytes)
            is_ret = x86Checker.is_ret(next_instruction_bytes)

            if is_positive_conditional_jmp_two_bytes or is_negative_conditional_jmp_two_bytes or is_call_two_bytes or is_jmp_two_bytes or is_call_one_byte or is_jmp_one_byte or is_positive_jmp_one_byte or is_negative_jmp_one_byte:
                if iteration_counter > MAX_ITERATIONS_BEFORE_STRINGS_DUMP:
                    self.save_execution_strings()
                    iteration_counter = 0

                # here i introduce optimization. If i see a positive/negative conditional being hit more than a certain threshold, i assume it is in a loop and so i force jump to next instruction with BP. I should take into account time (i.e. what if the instruction
                # is mentioned througout the code )

                if is_positive_conditional_jmp_two_bytes or is_positive_jmp_one_byte or is_negative_conditional_jmp_two_bytes or is_negative_jmp_one_byte:
                    if saved_eip not in self.conditional_jump_counts:
                        self.conditional_jump_counts[saved_eip] = 1
                    else:
                        self.conditional_jump_counts[saved_eip] += 1


                #Here if we hit the threshold of conditional jumps we skip....should take into account time or number of instructions since
                if (saved_eip in self.conditional_jump_counts) and (self.conditional_jump_counts[saved_eip] > CONDITIONAL_JUMP_THRESHOLD):
                    disassemble_result = self.disasm_at_va(saved_eip, 5)
                    print("Potential Loop Detected:")
                    print("[{}]{}:{}".format(self.trace.getCurrentThread(), hex(saved_eip), disassemble_result))

                    del self.conditional_jump_counts[saved_eip]  #if i hit the threshold i jump over and then i reinitiate the count??
                    self.jump_over_instruction_with_bp(saved_eip)


                # Only scan for strings when calls or jumps within the binary are performed. If not, the strings are likely passed as arguments.

                #We assume that at a certain point it will jump to the instruction after the negative jump.
                #if optimistic_mode and (is_negative_conditional_jmp_two_bytes or is_negative_jmp_one_byte):
                #    self.jump_over_instruction_with_bp(saved_eip)
                #else:
                self.trace.stepi()
                self.go_back_to_tracked_thread_if_current_not_tracked()

                eip = None
                if self.platform_bits == 32:
                    eip = self.trace.getRegister(REG_EIP)
                else:
                    eip = self.trace.getRegister(REG_RIP)


                can_stepout = self.can_stepout()

                # call [ADDRESS]
                module_and_function_name = (UNKNOWN_LIBRARY_TAG, UNKNOWN_FUNCTION_TAG)
                if can_stepout:

                    if track_library_calls:
                        module_and_function_name = self.address_to_module_and_function_name(eip)

                        function_arguments = []
                        called_function = module_and_function_name[1]
                        if track_library_call_arguments and (called_function in WindowsConstants.FUNCTION_ARGUMENT_PROCESSORS):
                            function_arguments = WindowsConstants.FUNCTION_ARGUMENT_PROCESSORS[module_and_function_name[1]](self)


                        if module_and_function_name[0] != MAIN_BINARY_TAG and module_and_function_name[0] != UNKNOWN_LIBRARY_TAG:
                            formatted_string = 'LibraryFunction:[{}]{}:{} {}:{} {}'.format(self.trace.getCurrentThread(), str(hex(saved_eip)), CALL_OR_JUMP_MNEMONIC, module_and_function_name[0], module_and_function_name[1], function_arguments)
                            print(formatted_string)
                            self.program_output_writter.write_string_to_file(formatted_string + os.linesep)


                    # We stepout if we don't want to stay within the library
                    if not run_through_instructions_outside_main_binary:
                        #disassemble_result = self.disasm_at_va_and_perform_operation(eip)
                        #print("{}:{}".format(hex(eip), disassemble_result))
                        self.step_out()
                        self.go_back_to_tracked_thread_if_current_not_tracked()

                #if cannot stepout, it means it is not a lib. We scan for strings. Lowers overhead.
                ##How about jmps????why am i not extracting with jumps??????????????????????????????
                else:

                    '''
                    ##We should probably extend this with far jumps and jumps to registers????
                    if is_call_one_byte or is_call_two_bytes:
                        # Here if we hit the threshold of calls, we stepout. Likely some utilitarian function...Here we never delete the key because, if the function is called more than threshold, we can be sure it is utilitarian
                        # There is a problem however: if we keep running the malware for too long, functions like C2 will be executed multiple times.
                        # There is also another problem: what about those core stub functions that call other functions based on offsets?? i will miss the offseted functions...
                        # These are corner cases. Will see. I should probably prompt the analyst for a verdict. This function has been called multiple times. Should we blacklist it?
                        # There are also two types of frequently called functions: e.g. string decoders which are called across the code once or twice but sum up to a bunch of references and those functions that keep getting called to process strings.
                        # What about linked libraries? My function can waste hours iterating through a statically linked printf...how to address this???
                        if eip in self.call_counts:
                            if self.call_counts[eip] > CALL_COUNT_THRESHOLD:
                                self.step_out()

                        else:
                            #What if i catch a routine that uses a call to resolve the current code position? it will neverreturn because it pops out the ret eip on the first instruction...
                            if eip not in self.call_counts:
                                self.call_counts[eip] = 1
                            else:
                                self.call_counts[eip] += 1
                    '''

                    self.extract_strings_from_memory(thorough_string_scan)


                eax_constant = None
                if self.platform_bits == 32:
                    eax_constant = REG_EAX
                else:
                    eax_constant = REG_RAX

                if track_library_call_returns and (called_function in WindowsConstants.FUNCTION_RESULT_PROCESSORS):
                    WindowsConstants.FUNCTION_RESULT_PROCESSORS[called_function](self, self.trace.getRegister(eax_constant))


                iteration_counter += 1
                continue

            # Removing this to speed things up
            # There is a problem here. The rep executes multiple times and the esi edis change so i may end up gettin access violations....The solution is to jump....
            elif is_rep:

                #if iteration_counter > MAX_ITERATIONS_BEFORE_STRINGS_DUMP:
                #    self.save_execution_strings()
                #    iteration_counter = 0

                #iteration_counter += 1

                #self.extract_strings_from_memory(thorough_string_scan)

                '''
                There is a problem with rep ret instructions.
                StackOverflow: Basically, there was an issue in the AMD's branch predictor when a single-byte ret immediately followed a conditional jump as in the code you quoted (and a few other situations), and the workaround was to add the rep prefix, which is ignored by 
                CPU but fixes the predictor penalty.
                '''
                if x86Checker.is_ret(next_instruction_bytes[1::]):
                    self.trace.stepi()
                    self.go_back_to_tracked_thread_if_current_not_tracked()
                else:
                    self.skip_rep()

                # Only scan for strings when calls or jumps within the binary are performed. If not, the strings are likely passed as arguments.

                continue

            elif is_ret:
                self.trace.stepi()
                #This is a very weird case where ret jumps to a library function. This can happen when the malware finishes execution or when a TLS function finishes.
                # Under such circumstances, i will simply run until the next BP. Normally, this does not happen.
                #Bear in mind that i am disabling anti-ani-analysis here
                if self.can_stepout():
                    top_level_functions_index += 1
                    if top_level_functions_index < len(top_level_functions):
                        next_top_level_eip = top_level_functions[top_level_functions_index]
                        print('Engines->VivisectWindowsEngine->run_through returned to Windows libraries code. Running to: {}'.format(hex(next_top_level_eip)))
                        self.set_bp_and_run(next_top_level_eip)
                 #here i should simply run free but i will keep following...
                continue

            elif is_loop:
                print("FOUND LOOOPPPPPPPPPPPPPPPPPPPP")
                continue

            # this is an optimization. If we don't hit an interesting instruction, i search ahead and jump there.
            # here i am disassembling because otherwise i would need to analyse the bytes ahead against one of my lists and that would be a bit of a pain depending on where i
            # start and how many bytes i read, etc.
            elif self.disasm_at_va_and_perform_operation(saved_eip, self.find_next_valid_instruction_and_run_to_it):
                continue

            else:
                self.trace.stepi()


