from Util.MemoryDataInterpreter import MemoryDataInterpreter

class OpenMutex:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):
        arguments_array = vivisect_engine.get_function_arguments(3)


        lp_mutex_attributes = arguments_array[0]
        b_inherit_handle = arguments_array[2]
        lp_name = arguments_array[3]

        mutex_name = ''
        if lp_name != 0x0:
            bytes = vivisect_engine.read_memory(lp_name, OpenMutex.DEFAULT_READ_SIZE)
            mutex_name = MemoryDataInterpreter.bytearray_to_ascii_string(bytes)

        return [hex(lp_mutex_attributes), bool(b_inherit_handle), mutex_name]