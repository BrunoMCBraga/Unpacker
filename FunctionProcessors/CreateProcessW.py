from Util.MemoryDataInterpreter import MemoryDataInterpreter

class CreateProcessW:

    DEFAULT_READ_SIZE = 50

    @staticmethod
    def get_arguments_list(vivisect_engine):

        arguments_array = vivisect_engine.get_function_arguments(10)

        lp_application_name = arguments_array[0]
        lp_command_line = arguments_array[1]
        lp_process_attributes = arguments_array[2]
        lp_thread_attributes = arguments_array[3]
        b_inherit_handles = arguments_array[4]
        dw_creation_flags = arguments_array[5]
        lp_environment = arguments_array[7]
        lp_current_directory = arguments_array[8]
        lp_startup_info = arguments_array[9]
        lp_process_information = arguments_array[10]

        application_name = None

        if lp_application_name != 0x0:
            application_name_bytes = vivisect_engine.read_memory(lp_parameter, CreateProcessA.DEFAULT_READ_SIZE)
            application_name = MemoryDataInterpreter.bytearray_to_uncicode_string(application_name_bytes)

        command_line = None

        if lp_command_line != 0x0:
            command_line_bytes = vivisect_engine.read_memory(lp_command_line, CreateProcessA.DEFAULT_READ_SIZE)
            command_line = MemoryDataInterpreter.bytearray_to_uncicode_string(command_line_bytes)


        current_directory = None

        if lp_current_directory != 0x0:
            current_directory_bytes = vivisect_engine.read_memory(lp_current_directory, CreateProcessA.DEFAULT_READ_SIZE)
            current_directory = MemoryDataInterpreter.bytearray_to_uncicode_string(current_directory_bytes)

        startup_info_bytes = None

        if lp_startup_info != 0x0:
            startup_info_bytes = vivisect_engine.read_memory(startup_info_bytes, CreateProcessA.DEFAULT_READ_SIZE)


        process_information_bytes = None

        if lp_process_information != 0x0:
            process_information_bytes = vivisect_engine.read_memory(lp_process_information, CreateProcessA.DEFAULT_READ_SIZE)


        return [application_name, command_line, hex(lp_process_attributes), hex(lp_thread_attributes), hex(b_inherit_handles), hex(dw_creation_flags), hex(lp_environment), current_directory, startup_info_bytes, process_information_bytes]