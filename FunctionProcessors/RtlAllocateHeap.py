class RtlAllocateHeap:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(3)

        heap_handle = arguments_array[0]
        flags = arguments_array[1]
        size = arguments_array[2]

        return [hex(heap_handle), hex(flags), size]

    @staticmethod
    def process_result(vivisect_engine, result):
        vivisect_engine.update_memory_map(result)