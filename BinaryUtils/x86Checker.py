class x86Checker:

    prefix_list = [0x64, 0x66, 0x67, 0xF3, 0xF0, 0x48, 0x41]

    @staticmethod
    def is_positive_conditional_jmp_two_bytes(bytes):

        if len(bytes) < 2:
            return False

        if len(bytes) > 2 and bytes[0] in x86Checker.prefix_list:
            bytes = bytes[1::]

        return (True if (bytes[0] == 0x0F and bytes[1] in [0x80, 0x84, 0x88, 0x8A]) else False)

    '''
    @staticmethod
    def is_positive_conditional_jmp_one_bytes(bytes):

        if len(bytes) == 0:
            return False


        if len(bytes) > 1 and bytes[0] in x86Checker.prefix_list:
            bytes = bytes[1::]

        return (True if bytes[0] in [0x70, 0x78, 0x74, 0x7A, 0xE3] else False)

    '''

    @staticmethod
    def is_negative_conditional_jmp_two_bytes(bytes):

        if len(bytes) < 2:
            return False

        if len(bytes) > 2 and bytes[0] in x86Checker.prefix_list:
            bytes = bytes[1::]

        return (True if (bytes[0] == 0x0F and bytes[1] in [0x81, 0x82, 0x83, 0x85, 0x86, 0x87, 0x89, 0x89, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F]) else False)

    '''
    @staticmethod
    def is_negative_conditional_jmp_one_bytes(bytes):

        if len(bytes) == 0:
            return False

        if len(bytes) > 1 and bytes[0] in x86Checker.prefix_list:
            bytes = bytes[1::]

        return (True if bytes[0] in [0x71, 0x79, 0x75, 0x72, 0x73, 0x76, 0x77, 0x7C, 0x7D, 0x7E, 0x7F, 0x7B] else False)
    '''

    @staticmethod
    def is_jmp_two_bytes(bytes):

        if len(bytes) < 2:
            return False

        if len(bytes) > 2 and bytes[0] in x86Checker.prefix_list:
            bytes = bytes[1::]

        modr = ((bytes[1] >> 3) & 7)
        return (True if bytes[0] == 0xFF and (modr == 4 or modr == 5) else False)


    @staticmethod
    def is_jmp_one_byte(bytes):

        if len(bytes) == 0:
            return False

        if len(bytes) > 1 and bytes[0] in x86Checker.prefix_list:
            bytes = bytes[1::]

        return (True if bytes[0] in [0xE9, 0xEA, 0xEB] else False)


    @staticmethod
    def is_positive_jmp_one_byte(bytes):

        if len(bytes) == 0:
            return False

        if len(bytes) > 1 and bytes[0] in x86Checker.prefix_list:
            bytes = bytes[1::]

        return (True if bytes[0] in [0x70, 0x74, 0x78, 0x7A, 0xE3] else False)

    @staticmethod
    def is_negative_jmp_one_byte(bytes):

        if len(bytes) == 0:
            return False

        if len(bytes) > 1 and bytes[0] in x86Checker.prefix_list:
            bytes = bytes[1::]

        return (True if bytes[0] in [0x71, 0x72, 0x73, 0x75, 0x76, 0x77, 0x79, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F] else False)

    @staticmethod
    def is_call_two_bytes(bytes):

        if len(bytes) < 2:
            return False

        if len(bytes) > 2 and bytes[0] in x86Checker.prefix_list:
            bytes = bytes[1::]

        modr = ((bytes[1] >> 3) & 7)
        return (True if (bytes[0] == 0xFF) and (modr == 2 or modr == 3) else False)


    @staticmethod
    def is_call_one_byte(bytes):

        if len(bytes) == 0:
            return False

        if len(bytes) > 1 and bytes[0] in x86Checker.prefix_list:
            bytes = bytes[1::]

        return (True if bytes[0] in [0xE8] else False)

    @staticmethod
    def is_rep(bytes):

        if len(bytes) == 0:
            return False

        if len(bytes) > 1 and bytes[0] in x86Checker.prefix_list:
            bytes = bytes[1::]

        return (True if bytes[0] in [0xF2, 0xF3] else False)

    @staticmethod
    def is_loop(bytes):

        if len(bytes) == 0:
            return False

        if len(bytes) > 1 and bytes[0] in x86Checker.prefix_list:
            bytes = bytes[1::]

        return (True if bytes[0] in [0xE0, 0xE1, 0xE2] else False)

    @staticmethod
    def is_ret(bytes):

        if len(bytes) == 0:
            return False

        if len(bytes) > 1 and bytes[0] in x86Checker.prefix_list:
            bytes = bytes[1::]

        return (True if bytes[0] in [0xC2, 0xC3, 0xCA, 0xCB, 0xCF] else False)
