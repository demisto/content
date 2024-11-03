import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import socket


''' CONSTANTS '''

''' CLIENT CLASS '''


class Server():
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.validate()

    def validate(self):
        is_ip = False
        try:
            socket.inet_aton(self.host)
            is_ip = True
        except OSError:
            is_ip = False
        if not is_ip:
            try:
                self.host = socket.gethostbyname(self.host)
            except Exception as err:
                return_error(f"{self.host} is not a valid IP nor does not resolve to an IP - {err}")

    def test_connect(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.port))
                s.sendall(b"test")
                data = s.recv(1024)
                if data.decode().startswith("Response"):
                    return 'ok'
                else:
                    return "There was an issue. Please check your Arduino code"
        except Exception as err:
            return_error(err)

    def send_data(self, value):
        data = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.port))
                s.sendall(value.encode())
                data = s.recv(1024)
        except Exception as err:
            return_error(err)
        return data


''' HELPER FUNCTIONS '''

''' COMMAND FUNCTIONS '''


def test_module(server: Server) -> str:
    return server.test_connect()


def arduino_set_pin_command(server: Server, args: dict) -> CommandResults:
    pin_type = args.get('pin_type')
    prefix = "Arduino.DigitalPins" if pin_type == "digital" else "Arduino.AnalogPins"
    pin_number = args.get('pin_number')
    try:
        pin_number = int(pin_number)  # type: ignore
    except Exception as err:
        return_error(f"'Pin number' must be a number - {err}")
    value = args.get('value')
    try:
        value = int(value)  # type: ignore
    except Exception as err:
        return_error(f"'Value' must be a number - {err}")
    result = int(server.send_data(f"set:{pin_type}:{pin_number},{value}"))
    results = [{
        "PinType": "Digital" if pin_type == "digital" else "Analog",
        "PinNumber": pin_number,
        "PinValue": result
    }]
    command_results = CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=['PinNumber', 'PinType'],
        outputs=results,
        readable_output=tableToMarkdown(f"Set pin {pin_number} on {server.host}({server.port}):", results)
    )
    return command_results


def arduino_get_pin_command(server: Server, args: dict) -> CommandResults:
    pin_type = args.get('pin_type')
    prefix = "Arduino.DigitalPins" if pin_type == "digital" else "Arduino.AnalogPins"
    pin_number = args.get('pin_number')
    try:
        pin_number = int(pin_number)  # type: ignore
    except Exception as err:
        return_error(f"'Pin number' must be a number - {err}")
    result: int = int(server.send_data(f"get:{pin_type}:{pin_number}"))
    results = [{
        "PinType": "Digital" if pin_type == "digital" else "Analog",
        "PinNumber": pin_number,
        "PinValue": result
    }]
    command_results = CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=['PinNumber', 'PinType'],
        outputs=results,
        readable_output=tableToMarkdown(f"Get pin {pin_number} on {server.host}({server.port}):", results)
    )
    return command_results


def arduino_send_data_command(server: Server, args: dict) -> CommandResults:
    data = args.get('data')
    result = server.send_data(data)
    results = [{
        "Sent": data,
        "Received": result.decode()
    }]
    command_results = CommandResults(
        outputs_prefix="Arduino.DataSend",
        outputs_key_field='Sent',
        outputs=results,
        readable_output=tableToMarkdown(f"Data sent to {server.host}({server.port}):", results)
    )
    return command_results


''' MAIN FUNCTION '''


def main():
    params = demisto.params()
    host = params.get('host')
    port = params.get('port')
    args = demisto.args()
    if "host" in args and "port" in args:
        host = args.get('host')
        port = args.get('port')
    try:
        port = int(port)
    except Exception as err:
        return_error(f"'Port' must be a number - {err}")
    command: str = demisto.command()
    demisto.debug(f'Command being called is {command}')

    commands = {
        'arduino-set-pin': arduino_set_pin_command,
        'arduino-get-pin': arduino_get_pin_command,
        'arduino-send-data': arduino_send_data_command
    }

    # try:
    server: Server = Server(host, port)

    if demisto.command() == 'test-module':
        return_results(test_module(server))

    elif command in commands:
        return_results(commands[command](server, args))

    else:
        return_error(f"{command} command not recognised")

    # Log exceptions and return errors
    # except Exception as e:
    #    demisto.error(traceback.format_exc())  # print the traceback
    #    return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
