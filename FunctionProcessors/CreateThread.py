from Util.MemoryDataInterpreter import MemoryDataInterpreter

class CreateThread:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(6)

        lp_thread_attributes = arguments_array[0]
        dw_stack_size = arguments_array[1]
        lp_start_address = arguments_array[2]
        lp_parameter = arguments_array[3]
        dw_creation_flags = arguments_array[4]
        lp_thread_id = arguments_array[5]

        thread_parameter = None

        if lp_parameter != 0x0:
            thread_parameter = vivisect_engine.read_memory(lp_parameter, CreateThread.DEFAULT_READ_SIZE)


        return [hex(lp_thread_attributes), dw_stack_size, hex(lp_start_address), thread_parameter, hex(dw_creation_flags), hex(lp_thread_id)]