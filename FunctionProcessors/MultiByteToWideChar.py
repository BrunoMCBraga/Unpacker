from Util.MemoryDataInterpreter import MemoryDataInterpreter

class MultiByteToWideChar:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(6)

        code_page = arguments_array[0]
        dw_flags = arguments_array[1]
        lp_multibyte_str = arguments_array[2]
        cb_multi_byte = arguments_array[3]
        lp_wide_char_str = arguments_array[4]
        cc_wide_char = arguments_array[5]

        source_bytes = None
        destination_bytes = None

        if lp_multibyte_str != 0x0:
            source_bytes = vivisect_engine.read_memory(lp_multibyte_str, cb_multi_byte)
            source_bytes = MemoryDataInterpreter.bytearray_to_ascii_string(source_bytes)


        if lp_wide_char_str != 0x0:
            destination_bytes = vivisect_engine.read_memory(lp_wide_char_str, cc_wide_char)

            #destination_bytes = MemoryDataInterpreter.bytearray_to_ascii_string(destination_bytes) #We don't do this because there may be garbage there. I will return a cast to string.

        return [hex(code_page), hex(dw_flags), source_bytes, hex(cb_multi_byte), destination_bytes, hex(cc_wide_char)]