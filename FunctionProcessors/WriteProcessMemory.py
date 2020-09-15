from Util.MemoryDataInterpreter import MemoryDataInterpreter

class WriteProcessMemory:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(5)

        h_process = arguments_array[0]
        lp_base_address = arguments_array[1]
        lp_buffer = arguments_array[2]
        n_size = arguments_array[3]
        lp_Number_of_bytes_written = arguments_array[4]

        extracted_bytes = None

        if lp_buffer != 0x0:
            bytes = vivisect_engine.read_memory(lp_buffer, WriteProcessMemory.DEFAULT_READ_SIZE)
            extracted_bytes = MemoryDataInterpreter.extract_bytes(bytes, n_size)

        return [h_process, hex(lp_base_address), n_size, lp_Number_of_bytes_written, extracted_bytes]