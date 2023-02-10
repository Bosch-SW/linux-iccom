from tests import *
from common import *

if __name__ == '__main__':
        iccom_device = []
        dummy_transport_device = []

        iccom_device.append("iccom.0")
        iccom_device.append("iccom.1")
        iccom_device.append("iccom.2")
        iccom_device.append("iccom.3")

        dummy_transport_device.append("dummy_transport.0")
        dummy_transport_device.append("dummy_transport.1")
        dummy_transport_device.append("dummy_transport.2")
        dummy_transport_device.append("dummy_transport.3")

        ## Create iccom device instances
        for x in iccom_device:
                create_iccom_device()

        # Create iccom device instances
        for x in dummy_transport_device:
                create_dummy_transport_device()

        # Link tranport device to iccom
        link_dummy_transport_device_to_iccom_device(dummy_transport_device[0], iccom_device[0])
        link_dummy_transport_device_to_iccom_device(dummy_transport_device[1], iccom_device[1])
        link_dummy_transport_device_to_iccom_device(dummy_transport_device[2], iccom_device[2])
        link_dummy_transport_device_to_iccom_device(dummy_transport_device[3], iccom_device[3])

        # Test #1
        iccom_data_exchange_to_transport_with_iccom_data_with_transport_data(dummy_transport_device[1], iccom_device[1])

        # Test #2
        iccom_data_exchange_to_transport_with_iccom_data_without_transport_data(dummy_transport_device[0], iccom_device[0])

        # Test #3
        iccom_data_exchange_to_transport_with_iccom_data_with_transport_data_wrong_payload_size(dummy_transport_device[2], iccom_device[2])

        #Test #4
        iccom_data_exchange_to_transport_with_iccom_data_with_transport_nack(dummy_transport_device[3], iccom_device[3])
