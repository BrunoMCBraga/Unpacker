import os

class GenericFileWritter:

    def __init__(self, file_path, mode):
        self.file_path = file_path
        self.mode = mode

    def write_strings_list_to_file(self, strings_list):

        try:
            with open(self.file_path, self.mode) as f:
                for string in strings_list:
                    f.write(string + os.linesep)

        except Exception as e:
            print("FileSystem->GenericFileWritter->write_strings_list_to_file:" + str(e))



    def write_string_to_file(self, string):

        try:
            with open(self.file_path, self.mode) as f:
                f.write(string)

        except Exception as e:
            print("FileSystem->GenericFileWritter->write_string_to_file:" + str(e))