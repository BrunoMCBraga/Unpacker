from Util.MemoryDataInterpreter import MemoryDataInterpreter

class atexit:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):
        arguments_array = vivisect_engine.get_function_arguments(1)

        func = arguments_array[0]

        return [hex(func)]