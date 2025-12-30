from capture.packet_capture import start_capture

if __name__ == "__main__":
    try:
        start_capture()
    except KeyboardInterrupt:
        print("\n[AZT-NO] Capture stopped by user.")
