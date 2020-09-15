from Util.MemoryDataInterpreter import MemoryDataInterpreter

class memset:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(3)

        dest = arguments_array[0]
        c = arguments_array[1]
        count = arguments_array[2]

        bytes = None

        if dest != 0x0:
            bytes = vivisect_engine.read_memory(dest, count)
            #extracted_bytes = MemoryDataInterpreter.extract_bytes(bytes, count)

        return [hex(dest), hex(c), count, bytes]