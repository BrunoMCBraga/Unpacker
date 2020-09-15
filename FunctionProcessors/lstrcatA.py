from Util.MemoryDataInterpreter import MemoryDataInterpreter

class lstrcatA:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(2)

        lpString1 = arguments_array[0]
        lpString2 = arguments_array[1]

        extracted_bytes1 = None
        extracted_bytes2 = None

        if lpString1 != 0x0 and lpString2 != 0x0:
            bytes1 = vivisect_engine.read_memory(lpString1, lstrcatA.DEFAULT_READ_SIZE)
            bytes2 = vivisect_engine.read_memory(lpString2, lstrcatA.DEFAULT_READ_SIZE)
            extracted_bytes1 = MemoryDataInterpreter.bytearray_to_ascii_string(bytes1)
            extracted_bytes2 = MemoryDataInterpreter.bytearray_to_ascii_string(bytes2)

        return [hex(lpString1), hex(lpString2), extracted_bytes1, extracted_bytes2]