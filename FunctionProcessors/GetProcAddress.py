from Util.MemoryDataInterpreter import MemoryDataInterpreter

class GetProcAddress:

    DEFAULT_READ_SIZE = 50
    @staticmethod
    def get_arguments_list(vivisect_engine):
        arguments_array = vivisect_engine.get_function_arguments(2)

        h_module = arguments_array[0]
        l_proc_name = arguments_array[1]


        function_name = ''

        if l_proc_name != 0x0:
            bytes = vivisect_engine.read_memory(l_proc_name, GetProcAddress.DEFAULT_READ_SIZE)
            function_name = MemoryDataInterpreter.bytearray_to_ascii_string(bytes)


        return [hex(h_module), function_name]

