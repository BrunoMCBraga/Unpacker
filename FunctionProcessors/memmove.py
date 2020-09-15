from Util.MemoryDataInterpreter import MemoryDataInterpreter

class memmove:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(3)

        dest = arguments_array[0]
        src = arguments_array[1]
        count = arguments_array[2]

        bytes = None

        if src != 0x0:
            bytes = vivisect_engine.read_memory(src, count)
            #extracted_bytes = MemoryDataInterpreter.extract_bytes(bytes, count)

        return [hex(dest), hex(src), count, bytes]