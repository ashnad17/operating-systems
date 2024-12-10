
import datetime, time  # to calculate the time delta of packet transmission
import logging, sys  # to write the log
import socket  # Core lib, to send packet via UDP socket
from threading import Thread  # (Optional)threading will make the timer easily implemented
import random

BUFFERSIZE = 1024


class Sender:
    def __init__(self, sender_port: int, receiver_port: int, filename: str, max_win: int, rto: int) -> None:
        '''
        The Sender will be able to connect the Receiver via UDP
        :param sender_port: the UDP port number to be used by the sender to send PTP segments to the receiver
        :param receiver_port: the UDP port number on which receiver is expecting to receive PTP segments from the sender
        :param filename: the name of the text file that must be transferred from sender to receiver using your reliable transport protocol.
        :param max_win: the maximum window size in bytes for the sender window.
        :param rot: the value of the retransmission timer in milliseconds. This should be an unsigned integer.
        '''
        self.sender_port = int(sender_port)
        self.receiver_port = int(receiver_port)
        self.sender_address = ("127.0.0.1", self.sender_port)
        self.receiver_address = ("127.0.0.1", self.receiver_port)
        self.filename = filename
        self.window_size = int(max_win)/1000
        self.rto = rto
        self.window = []
        self.closing = False
        self.connection_secured = False
        

        # init the UDP socket
        logging.debug(f"The sender is using the address {self.sender_address}")
        self.sender_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.sender_socket.bind(self.sender_address)


        #  (Optional) start the listening sub-thread first
        self._is_active = True  # for the multi-threading
        listen_thread = Thread(target=self.listen)
        listen_thread.daemon = True
        listen_thread.start()

        pass

    def ptp_open(self):
        # SYN - initiate two way handshake
        self.syn_try += 1
        ISN_int = int.from_bytes(self.ISN, "big")
        typeSYN = (2).to_bytes(2, byteorder='big', signed=False)
        segment = typeSYN + self.ISN
        self.ack_received = False
        with open("Sender_log.txt", "a+") as logfile:
            if self.syn_try == 1:
                self.start_time = time.time()
            logfile.write("snd".ljust(7) + str(round((time.time() - self.start_time), 2)).ljust(7) + "SYN".ljust(7) + str(ISN_int).ljust(7) + str(0).ljust(7) + "\n")
        logging.debug(f"snd\t\t{round((time.time() - self.start_time), 2)}\t\tSYN\t\t{ISN_int}\t\t0")
        
        # send to receiver
        self.sender_socket.sendto(segment, self.receiver_address)

        # start timer for syn segment
        self.timed_out = False
        timer_thread = Thread(target = self.timer)
        timer_thread.start()

        # wait for ack 
        while not self.timed_out and not self.ack_received:
            pass
        pass

    def ptp_send(self):

        f = open(self.filename, "r")
        self.i = 0
        self.window = []

        # continually read data through file
        while True:
            data = f.read(1000)
            if data:

                # if window is "full", wait
                while len(self.window) == int(self.window_size):
                    pass

                # if this is the first packet
                if self.i == 0 and len(self.window) == 0 and len(data) == 1000:

                    seq_num = int.from_bytes(self.last_ack_received, "big") + (len(self.window) * len(data))

                    if seq_num > 65535:
                        seq_num = (seq_num - (65535) - 1).to_bytes(2, "big")
                    else:
                        seq_num = seq_num.to_bytes(2, "big")

                else:
                    if self.i == 0 and len(self.window) == 0:
                        seq_num = int.from_bytes(self.last_ack_received, "big")
                    else:
                        seq_num = int.from_bytes(seq_num, "big") + 1000
                
                    if seq_num > 65535:
                        seq_num = (seq_num - (65535) - 1).to_bytes(2, "big")
                    else:
                        seq_num = seq_num.to_bytes(2, "big")
                    
                # set values for segment
                seq_num_int = int.from_bytes(seq_num, "big")
                typeDATA = (0).to_bytes(2, byteorder='big', signed=False)
                segment = typeDATA + seq_num + data.encode('utf-8')
                
                # add sent segment to window
                self.window.append({"data": data, "seq_num": seq_num_int})
                
                # send segment
                self.sender_socket.sendto(segment, self.receiver_address)

                # record in log
                with open("Sender_log.txt", "a+") as logfile:
                    logfile.write("snd".ljust(7) + str(round((time.time() - self.start_time), 2)).ljust(7) + "DATA".ljust(7) + str(seq_num_int).ljust(7) + str(len(data)).ljust(7) + "\n")
                logging.debug(f"snd \t\t{round((time.time() - self.start_time), 2)}\t\tDATA \t\t{seq_num_int}\t\t{len(data)}")

                # if window length is 1, transfer timer to first segment
                if len(self.window) == 1:
                    self.ack_received = False
                    self.timed_out = False
                    timer_thread = Thread(target = self.timer)
                    timer_thread.start()
                self.i += 1
            else:
                break

            # do not exit send function until all acks are received
            while not self.timed_out and self.ack_received:
                break
        # todo add codes heres
        
        if self.i == int(self.window_size - 1) and not self.ack_received:
            send_last_unacked_segment(self)
        
        while len(self.window) >0:
            pass
        # if still as above, send reset for last segment
        pass


    def ptp_close(self):
        # closing, similar to SYNACK
        self.fin_try += 1
        self.closing = True
        typeFIN = (3).to_bytes(2, byteorder='big', signed=False)
        seq_num_int = int.from_bytes(self.last_ack_received, "big") + 1
        if seq_num_int > 65535:
            seq_num = (seq_num_int - 65535 - 1).to_bytes(2, "big")
        else:
            seq_num = (seq_num_int).to_bytes(2, "big")

        segment = typeFIN + seq_num
        self.ack_received = False
        with open("Sender_log.txt", "a+") as logfile:
            logfile.write("snd".ljust(7) + str(round((time.time() - self.start_time), 2)).ljust(7) + "FIN".ljust(7) + str(seq_num_int).ljust(7) + str(0).ljust(7) + "\n")
        logging.debug(f"snd\t\t{round((time.time() - self.start_time), 2)}\t\tFIN\t\t{seq_num_int}\t\t0")
        self.sender_socket.sendto(segment, self.receiver_address)
        self.timed_out = False
        timer_thread = Thread(target = self.timer)
        timer_thread.start()
        while not self.timed_out and not self.ack_received:
            pass
        pass


    def listen(self):
        '''(Multithread is used)listen the response from receiver'''
        logging.debug("Sub-thread for listening is running")
        while self._is_active:
            # todo add socket
            # store incoming message
            incoming_message, _ = self.sender_socket.recvfrom(BUFFERSIZE)
            acknum = int.from_bytes(incoming_message[2:4], "big")

            # write to log
            with open("Sender_log.txt", "a+") as logfile:
                logfile.write("rcv".ljust(7) + str(round((time.time() - self.start_time), 2)).ljust(7) + "ACK".ljust(7) + str(acknum).ljust(7) + str(0).ljust(7) + "\n")
            logging.debug(f"rcv\t\t{round((time.time() - self.start_time), 2)}\t\tACK\t\t{acknum}\t\t0")
            self.ack_received = True
    
            
            # this is the ack for a synack
            if self.last_ack_received == '':
                self.connection_secured = True
                self.last_ack_was_syn = True
                self.last_ack_received = incoming_message[2:4]
            elif self.closing:
                self.connection_secured = False
                self._is_active = False
            else:
                # Duplicate ack
                if self.last_ack_received == incoming_message[2:4] and not self.last_ack_was_syn:
                    # repeated ack send last 
                    self.duplicate_acks += 1
                    if self.duplicate_acks == 3:
                        send_last_unacked_segment(self)
                        self.duplicate_acks = 0
                else:
                    # normal ack
                    self.duplicate_acks = 1
                    self.last_ack_was_syn = False
                    val = int.from_bytes(self.last_ack_received, "big")
                    if int.from_bytes(incoming_message[2:4], "big") - val > 1000:
                        val += 1000
                    if len(self.window) > 0:
                        if len(self.window) == 1:
                            del self.window[0]
                        else:
                            for i, data in enumerate(self.window):
                                if self.window[i]['seq_num'] == val:
                                    break
                                del self.window[i]
                                i = i -1
                            del self.window[i]
                    self.last_ack_received = incoming_message[2:4]
                    if len(self.window) > 0:
                        self.ack_received = False
                        self.i = self.i - 1
                        self.timed_out = False
                        timer_thread = Thread(target = self.timer)
                        timer_thread.start()


    def run(self):
        '''
        This function contain the main logic of the receiver
        '''
        # todo add/modify codes here
        open('Sender_log.txt', 'w').close()


        self.syn_try = 0
        self.fin_try = 0
        ISN_int = random.randint(0, 65535)
        self.ISN = ISN_int.to_bytes(2, byteorder = "big", signed=False)
        self.last_ack_received = ''
        while self.syn_try < 4 and not self.connection_secured:
            logging.debug("Attempting to connect")
            logging.debug(f"trying to connect attempt: {self.syn_try}")
            self.ptp_open()
        if not self.connection_secured:
            logging.debug("Connection failed, not sending file")
            typeRESET = (4).to_bytes(2, byteorder='big', signed=False)
            reply_message = typeRESET + b'0'
            with open("Sender_log.txt", "a+") as logfile:
                logfile.write(f"snd".ljust(7) + str(round((time.time() - self.start_time), 2)).ljust(7) + "RESET".ljust(7) + str(0).ljust(7) + str(0).ljust(7) + "\n")
            logging.debug(f"snd\t\t{round((time.time() - self.start_time), 2)}\t\RESET\t\t0\t\t0")
            self.sender_socket.sendto(reply_message, self.receiver_address)
            self._is_active = False
            self.ack_received = True
            exit()
        else:
            logging.debug("Connection success, now sending file")
            self.ptp_send()
            logging.debug("File sent, connection being closed")
            while self.fin_try < 4 and self.connection_secured:
                logging.debug(f"Attempting to close attempt: {self.fin_try}")
                self.ptp_close()
            if self.connection_secured:
                typeRESET = (4).to_bytes(2, byteorder='big', signed=False)
                reply_message = typeRESET + b'0'
                with open("Sender_log.txt", "a+") as logfile:
                    logfile.write(f"snd".ljust(7) + str(round((time.time() - self.start_time), 2)).ljust(7) + "RESET".ljust(7) + str(0).ljust(7) + str(0).ljust(7) + "\n")
                logging.debug(f"snd\t\t{round((time.time() - self.start_time), 2)}\t\RESET\t\t0\t\t0")
                self.sender_socket.sendto(reply_message, self.receiver_address)
            logging.debug("Connection Closed")
            self._is_active = False

            sys.exit()

    def timer(self):
        ''' Multithread to time each STP ack'''
        time_started = time.time()
        while not self.ack_received:
            if time.time() >= time_started + (int(self.rto)/1000):
                self.timed_out = True
                if self.connection_secured and not self.closing:
                    send_last_unacked_segment(self)
                return
    
    
def send_last_unacked_segment(self):
    if len(self.window) > 0:
        data = self.window[0]['data']
        seq_num = self.last_ack_received
        seq_num_int = int.from_bytes(seq_num, "big")
        typeDATA = (0).to_bytes(2, byteorder='big', signed=False)
        segment = typeDATA + seq_num + data.encode('utf-8')
        self.sender_socket.sendto(segment, self.receiver_address)
        with open("Sender_log.txt", "a+") as logfile:
            logfile.write("snd".ljust(7) + str(round((time.time() - self.start_time), 2)).ljust(7) + "DATA".ljust(7) + str(seq_num_int).ljust(7) + str(len(data)).ljust(7) +  "\n")
        logging.debug(f"snd\t\t{(round((time.time() - self.start_time), 2))}\t\tDATA\t\t{seq_num_int}\t\t{len(data)}")
        self.timed_out = False
        timer_thread = Thread(target = self.timer)
        timer_thread.daemon = True
        timer_thread.start()
        
if __name__ == '__main__':
    # logging is useful for the log part: https://docs.python.org/3/library/logging.html
    logging.basicConfig(
        # filename="Sender_log.txt",
        stream=sys.stderr,
        level=logging.DEBUG,
        format='%(asctime)s,%(msecs)03d %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d:%H:%M:%S')

    if len(sys.argv) != 6:
        print(
            "\n===== Error usage, python3 sender.py sender_port receiver_port FileReceived.txt max_win rot ======\n")
        exit(0)

    sender = Sender(*sys.argv[1:])
    sender.run()

