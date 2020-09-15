class VirtualAlloc:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(5)

        lp_address = arguments_array[0]
        dw_size = int(arguments_array[1])
        fl_allocation_type = arguments_array[2]
        fl_protect = arguments_array[3]

        return [hex(lp_address), dw_size, hex(fl_allocation_type), hex(fl_protect)]

    @staticmethod
    def process_result(vivisect_engine, result):
        vivisect_engine.update_memory_map(result)