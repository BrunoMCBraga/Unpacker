from Util.MemoryDataInterpreter import MemoryDataInterpreter

class SetUnhandledExceptionFilter:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):
        arguments_array = vivisect_engine.get_function_arguments(1)

        lp_top_level_exception_filter = arguments_array[0]

        return [hex(lp_top_level_exception_filter)]