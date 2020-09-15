from Util.MemoryDataInterpreter import MemoryDataInterpreter

class GetStringTypeW:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(4)

        dw_info_type = arguments_array[0]
        lp_src_str = arguments_array[1]
        cch_src = arguments_array[2]
        lp_char_type = arguments_array[3]

        source_string = None
        destination_bytes = None

        if lp_src_str != 0x0:
            source_bytes = vivisect_engine.read_memory(lp_src_str, cch_src)
            source_string = MemoryDataInterpreter.bytearray_to_unicode_string(source_bytes)

            destination_bytes = vivisect_engine.read_memory(lp_char_type, cch_src)

        return [hex(dw_info_type), source_string, cch_src, destination_bytes]