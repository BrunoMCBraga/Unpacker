class GlobalAlloc:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(2)

        dw_flags = arguments_array[0]
        dw_bytes = arguments_array[1]

        return [hex(dw_flags), dw_bytes]

    @staticmethod
    def process_result(vivisect_engine, result):
        vivisect_engine.update_memory_map(result)