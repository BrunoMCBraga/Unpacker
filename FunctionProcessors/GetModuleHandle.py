from Util.MemoryDataInterpreter import MemoryDataInterpreter

class GetModuleHandle:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):
        arguments_array = vivisect_engine.get_function_arguments(1)

        lp_module_name = arguments_array[0]

        module_name = ''
        if lp_module_name != 0x0:
            bytes = vivisect_engine.read_memory(lp_module_name, GetModuleHandle.DEFAULT_READ_SIZE)
            module_name = MemoryDataInterpreter.bytearray_to_ascii_string(bytes)

        return [module_name]