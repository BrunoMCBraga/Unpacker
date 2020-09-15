
import sys
import argparse
import vtrace
from Engines.VivisectWindowsEngine import VivisectWindowsEngine
from Util.TimeStampGenerator import TimeStampGenerator

from FileSystem.GenericFileWritter import GenericFileWritter

# The following MUST be done otherwise windows catches the stopped program
# in a horrible attempt to "help".
# Go to the following registry location and change the value data to 1.
# HKEY_CURRENT_USER\Software\ Microsoft\Windows\Windows Error Reporting\DontShowUI

#######################################################################

STRINGS_OUTPUT_FILE_NAME_PREFIX = '{}\\Strings-{}.txt'
PROGRAM_OUTPUT_FILE_NAME_PREFIX = '{}\\Output-{}.txt'

######################################################################
#TODO:inspect if x86 or x64



if __name__ == "__main__":
    # --b C:\Users\root\Desktop\tr1.exe --a "" --so D:\\ --po D:\\
    parser = argparse.ArgumentParser(description='String Extractor.')
    parser.add_argument('--b', metavar='BINARY_PATH', type=str, help='path for binary')
    parser.add_argument('--a', metavar='ARGUMENTS', type=str, help='arguments for the binary to be executed')
    parser.add_argument('--so', metavar='STRINGS_PATH', type=str, help='path where strings file is stored')
    parser.add_argument('--po', metavar='OUTPUT_PATH', type=str, help='path where program output is stored (e.g. intermediate EIPs, library calls...)')
    parser.add_argument('--sa', metavar='STARTING_ADDRESS', type=str, help='address where execution should start')

    args = parser.parse_args()
    strings_output_writter = GenericFileWritter(
        STRINGS_OUTPUT_FILE_NAME_PREFIX.format(args.so, TimeStampGenerator.generate_timestamp()), 'w')
    program_output_writter = GenericFileWritter(
        PROGRAM_OUTPUT_FILE_NAME_PREFIX.format(args.po, TimeStampGenerator.generate_timestamp()), 'a')

   
    engine = VivisectWindowsEngine(args.b, args.a, strings_output_writter, program_output_writter, int(args.sa, 16) if args.sa != None else 0x0)

    # Get the current trace object from vtrace

    #try:
        # If True and Panda, it hangs...
        # run_through(self, run_through_instructions_outside_main_binary, thorough_string_scan, track_library_calls, track_library_call_arguments, track_library_call_returns, turbo_mode)
    engine.run_through(False, True, True, True, False,  False)  # The false is causing a crash on 32 bit apps......Try True with Gh0st. Without this i jump to entrypoint.
    #except Exception as e:
    #    print('Main->engine.run_through: ' + str(e))
    sys.exit(0)