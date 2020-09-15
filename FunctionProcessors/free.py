
class free:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(1)

        memblock = arguments_array[0]

        bytes = None

        #It is possible to free only based on base address ignoring size
        if memblock != 0x0:
            address_size_from_cache = vivisect_engine.get_address_size_for_memory(memblock)
            bytes = vivisect_engine.read_memory(memblock, address_size_from_cache)

        return [hex(memblock), bytes]
