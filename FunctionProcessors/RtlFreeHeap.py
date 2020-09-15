
class RtlFreeHeap:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(3)

        heap_handle = arguments_array[0]
        flags = int(arguments_array[1])
        base_address = arguments_array[2]

        bytes = None

        #It is possible to free only based on base address ignoring size
        if base_address != 0x0:
            address_size_from_cache = vivisect_engine.get_address_size_for_memory(base_address)
            bytes = vivisect_engine.read_memory(base_address, address_size_from_cache)

        return [hex(heap_handle), hex(flags), hex(base_address), bytes]
