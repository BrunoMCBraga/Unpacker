
class LocalFree:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(1)

        h_mem = arguments_array[0]

        bytes = None

        #It is possible to free only based on base address ignoring size
        if h_mem != 0x0:
            address_size_from_cache = vivisect_engine.get_address_size_for_memory(h_mem)
            bytes = vivisect_engine.read_memory(h_mem, address_size_from_cache)

        return [hex(h_mem), bytes]
