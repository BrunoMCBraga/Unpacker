class LocalAlloc:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(2)

        u_flags = arguments_array[0]
        u_bytes = arguments_array[1]

        return [hex(u_flags), u_bytes]

    @staticmethod
    def process_result(vivisect_engine, result):
        vivisect_engine.update_memory_map(result)