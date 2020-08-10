from p0f import P0f, P0fException
from subprocess import Popen, DEVNULL
from signal import SIGTERM
from time import sleep
import os


# Wrapper for P0f subprocess
class P0f_client():
    def __init__(self, named_socket, interface):
        self.named_socket = named_socket 

        try:
            # Remove socket if exists
            os.remove(named_socket)         
        except OSError:
            pass

        # ignore stdout, but keep stderr prints
        if interface is None:
            self.proc = Popen(["p0f", "-p", "-s", named_socket], stdout=DEVNULL)
        else:
            self.proc = Popen(["p0f", "-p", "-s", named_socket, "-i", interface], stdout=DEVNULL)
        elapsed = 0.0

        # busy wait for p0f process to open a socket
        while not os.path.exists(named_socket):
            sleep(0.1)
            elapsed += 0.1

            if elapsed >= 1.0:
                # If took more than a second to open the socket, terminate
                self.cleanup()
                raise Exception("Error creating socket - Timeout exceeded")

        self.instance = P0f(str(named_socket))

    def cleanup(self):
        # Terminate the passive scan process
        self.proc.terminate()
       
        # Remove socket if exists
        try:
            os.remove(self.named_socket)         
        except OSError:
            # Ignore file doesn't exist, also ignore other OSErrors
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.cleanup()

    def get_data(self, ip):
        data = None

        try:
            data = self.instance.get_info(ip)
        except P0fException as e:
            # Invalid query was sent to p0f. Maybe the API has changed.
            print(e)
        except KeyError as e:
            # No data is available for this IP address.
            print(e)
        except ValueError as e:
            # p0f returned invalid constant values. Maybe the API has changed.
            print(e)

        return data
