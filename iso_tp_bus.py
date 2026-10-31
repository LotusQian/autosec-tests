"""python-can 与 can-isotp 的胶水层。

isotp 2.x 里 TransportLayer 只是纯协议状态机，需要外部不断调用 process()；
CanStack 才是"绑在 python-can 总线上、自己驱动状态机"的那一层，所以用 CanStack。

换到真实硬件时只改 open_bus() 的参数：
    open_bus(interface="pcan", channel="PCAN_USBBUS1", bitrate=500000)      # PEAK PCAN-USB FD
    open_bus(interface="gs_usb", channel=0, bitrate=500000)                 # CANable / candleLight
    open_bus(interface="slcan", channel="COM5", bitrate=500000)
    open_bus(interface="vector", channel=0, bitrate=500000, app_name="CANalyzer")
"""
import can
import isotp


def open_bus(interface="virtual", channel="autosec-demo", **kwargs):
    """打开一条 CAN 总线。默认虚拟总线，无需硬件。"""
    if interface == "virtual":
        kwargs.pop("bitrate", None)      # 虚拟总线不接受 bitrate
    return can.Bus(interface=interface, channel=channel, **kwargs)


def make_transport(bus, rxid, txid, blocking_send=True):
    """在一条总线上建立 ISO-TP 层。rxid=接收 ID, txid=发送 ID。

    isotp 2.x 的 CanStack 需要 start() 才会起内部收发线程；
    不调用 start() 就只能手动 process()，否则 send() 会 BlockingSendTimeout。
    """
    address = isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=rxid, txid=txid)
    stack = isotp.CanStack(bus=bus, address=address, params={"blocking_send": blocking_send})
    stack.start()
    return stack


def close_transport(stack):
    try:
        stack.stop()
    except Exception:
        pass
