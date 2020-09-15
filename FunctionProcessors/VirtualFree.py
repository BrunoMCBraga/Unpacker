
class VirtualFree:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(3)

        lp_address = arguments_array[0]
        dw_size = arguments_array[1]
        dw_free_type = arguments_array[2]

        bytes = None

        #It is possible to free only based on base address ignoring size
        if lp_address != 0x0:
            address_size_from_cache = vivisect_engine.get_address_size_for_memory(lp_address)
            bytes = vivisect_engine.read_memory(lp_address, address_size_from_cache)

        return [hex(lp_address), dw_size, hex(dw_free_type), bytes]
