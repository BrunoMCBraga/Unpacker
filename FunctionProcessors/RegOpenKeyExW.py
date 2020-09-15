from Util.MemoryDataInterpreter import MemoryDataInterpreter

class RegOpenKeyExW:
    DEFAULT_READ_SIZE = 5000

    @staticmethod
    def get_arguments_list(vivisect_engine):
        arguments_array = vivisect_engine.get_function_arguments(5)

        h_key = arguments_array[0]
        lp_subkey = arguments_array[1]
        ul_options = arguments_array[2]
        sam_desired = arguments_array[3]
        phk_result = arguments_array[4]

        subkey_name = ''

        if lp_subkey != 0x0:
            bytes = vivisect_engine.read_memory(lp_subkey, RegOpenKeyExW.DEFAULT_READ_SIZE)
            subkey_name = MemoryDataInterpreter.bytearray_to_unicode_string(bytes)

        return [hex(h_key), subkey_name, hex(ul_options), hex(sam_desired), hex(phk_result)]