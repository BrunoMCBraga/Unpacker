from Util.MemoryDataInterpreter import MemoryDataInterpreter

class RtlUserThreadStart:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(4)

        arg1 = arguments_array[0]
        arg2 = arguments_array[1]
        arg3 = arguments_array[2]
        arg4 = arguments_array[3]


        return [hex(arg1), hex(arg2), hex(arg3), hex(arg4)]