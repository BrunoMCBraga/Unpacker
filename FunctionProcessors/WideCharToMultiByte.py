from Util.MemoryDataInterpreter import MemoryDataInterpreter

class WideCharToMultiByte:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(8)

        code_page = arguments_array[0]
        dw_flags = arguments_array[1]
        lp_wide_char_str = arguments_array[2]
        cch_wide_char = arguments_array[3]
        lp_multi_byte_str = arguments_array[4]
        cb_multi_byte = arguments_array[5]
        lp_default_char = arguments_array[6]
        lp_used_default_char = arguments_array[7]


        source_bytes = None
        destination_bytes = None

        if lp_wide_char_str != 0x0:
            source_bytes = vivisect_engine.read_memory(lp_wide_char_str, cch_wide_char)
            source_bytes = MemoryDataInterpreter.bytearray_to_unicode_string(source_bytes)

            #destination_bytes = MemoryDataInterpreter.bytearray_to_ascii_string(destination_bytes) #We don't do this because there may be garbage there. I will return a cast to string.

        if lp_multi_byte_str != 0x0:
            destination_bytes = vivisect_engine.read_memory(lp_multi_byte_str, cb_multi_byte)

        return [hex(code_page), hex(dw_flags), source_bytes, cch_wide_char, destination_bytes, cb_multi_byte, hex(lp_default_char), hex(lp_used_default_char)]