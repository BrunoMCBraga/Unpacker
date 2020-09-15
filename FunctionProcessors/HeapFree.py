
class HeapFree:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(3)

        h_heap = arguments_array[0]
        dw_flags = arguments_array[1]
        lp_mem = arguments_array[2]

        bytes = None

        #It is possible to free only based on base address ignoring size
        if lp_mem != 0x0:
            address_size_from_cache = vivisect_engine.get_address_size_for_memory(lp_mem)
            bytes = vivisect_engine.read_memory(lp_mem, address_size_from_cache)

        return [hex(h_heap), hex(dw_flags), hex(lp_mem), bytes]
