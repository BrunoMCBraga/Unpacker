class malloc:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(1)

        size = arguments_array[0]

        return [size]

    @staticmethod
    def process_result(vivisect_engine, result):
        vivisect_engine.update_memory_map(result)