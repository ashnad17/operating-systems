
import datetime, time  # to calculate the time delta of packet transmission
import logging, sys  # to write the log
import socket  # Core lib, to send packet via UDP socket
from threading import Thread  # (Optional)threading will make the timer easily implemented
import random  # for flp and rlp function

BUFFERSIZE = 1024


class Receiver:
    def __init__(self, receiver_port: int, sender_port: int, filename: str, flp: float, rlp: float) -> None:
        '''
        The server will be able to receive the file from the sender via UDP
        :param receiver_port: the UDP port number to be used by the receiver to receive PTP segments from the sender.
        :param sender_port: the UDP port number to be used by the sender to send PTP segments to the receiver.
        :param filename: the name of the text file into which the text sent by the sender should be stored
        :param flp: forward loss probability, which is the probability that any segment in the forward direction (Data, FIN, SYN) is lost.
        :param rlp: reverse loss probability, which is the probability of a segment in the reverse direction (i.e., ACKs) being lost.

        '''
        self.address = "127.0.0.1"  # change it to 0.0.0.0 or public ipv4 address if want to test it between different computers
        self.receiver_port = int(receiver_port)
        self.sender_port = int(sender_port)
        self.server_address = (self.address, self.receiver_port)
        self.filename = filename
        self.flp = float(flp)
        self.rlp = float(rlp)

        # init the UDP socket
        # define socket for the server side and bind address
        logging.debug(f"The sender is using the address {self.server_address} to receive message!")
        self.receiver_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.receiver_socket.bind(self.server_address)
        pass

    def run(self) -> None:
        '''
        This function contain the main logic of the receiver
        '''
        self.buffer = []
        self.seqs_received = []
        open('Receiver_log.txt', 'w').close()
        open('FileReceived.txt', 'w').close()
        self.start_time = time.time()
        close_conn = False
        self.connection_secured = False
        self.packet_lost = False
        while True:
            time.sleep(0.15)
            randval = random.uniform(0.0, 1.0)
            self.incoming_message, self.sender_address = self.receiver_socket.recvfrom(BUFFERSIZE)
            seq_num_int = int.from_bytes(self.incoming_message[2:4], "big")

            # If reset sent
            if int.from_bytes(self.incoming_message[:2], "big") == 4:
                with open("Receiver_log.txt", "a+") as logfile:
                    logfile.write(f"rcv".ljust(7) + str(round((time.time() - self.start_time), 2)).ljust(7) + "RESET".ljust(7) + str(0).ljust(7) + str(0).ljust(7) + "\n")
                logging.debug(f"snd\t\t{round((time.time() - self.start_time), 2)}\t\RESET\t\t0\t\t0")
                exit()
            # if segment not lost
            elif randval >= self.flp:
                # try to receive any incoming message from the sender
                self.last_seq_received = self.incoming_message[2:4]
                # if segment is SYN or FIN
                if self.incoming_message[0:2] == (2).to_bytes(2, "big") or self.incoming_message[0:2] == (3).to_bytes(2, "big"):
                    seq_num_int = int.from_bytes(self.incoming_message[2:4], "big")

                    # If SYN
                    if self.incoming_message[0:2] == (2).to_bytes(2, "big"):
                        # If first packet has not been lost and timer has not started
                        if not self.packet_lost:
                            self.start_time = time.time()
                        with open("Receiver_log.txt", "a+") as logfile:
                            logfile.write("rcv".ljust(7) + str(round((time.time() - self.start_time), 2)).ljust(7) + "SYN".ljust(7) + str(seq_num_int).ljust(7) + str(0).ljust(7) + "\n")
                        logging.debug(f"rcv\t\t{round((time.time() - self.start_time), 2)}\t\SYN\t\t{seq_num_int}\t\t{0}")
                        self.connection_secured = True
                    else:
                        # Write to log
                        with open("Receiver_log.txt", "a+") as logfile:
                            logfile.write("rcv".ljust(7) + str(round((time.time() - self.start_time), 2)).ljust(7) + "FIN".ljust(7) + str(seq_num_int).ljust(7) + str(0).ljust(7) + "\n")
                        logging.debug(f"rcv\t\t{round((time.time() - self.start_time), 2)}\t\FIN\t\t{seq_num_int}\t\t{0}")
                        close_conn = True
                    # If reply ACK has not been "lost"
                    if randval >= self.rlp:
                        reply_seqno = find_reply_seqno(self)
                        self.expected_seq = reply_seqno
                        typeACK = (1).to_bytes(2, byteorder='big', signed=False)
                        reply_message = typeACK + reply_seqno
                        send_ack(self, reply_message)
                        if close_conn:
                            exit()
                else:

                    data = self.incoming_message[4:]
                    # write to log
                    with open("Receiver_log.txt", "a+") as logfile:
                        logfile.write("rcv".ljust(7) + str(round((time.time() - self.start_time), 2)).ljust(7) + "DATA".ljust(7) + str(seq_num_int).ljust(7) + str(len(data)).ljust(7) + "\n")
                    logging.debug(f"rcv\t\t{round((time.time() - self.start_time), 2)}\t\tDATA\t\t{seq_num_int}\t\t{len(data)}")

                    # set data length for segments less than MSS
                    if int.from_bytes(self.incoming_message[2:4], "big") - int.from_bytes(self.last_seq_received, "big") <= 1000:
                        if self.incoming_message[2:4] not in self.seqs_received:
                            with open(self.filename, "ab+") as file:
                                file.write(self.incoming_message[4:])
                            self.seqs_received.append(self.incoming_message[2:4])
        
                        data_length = len(self.incoming_message[4:])
                    else:
                        self.buffer.append(self.incoming_message)
                    
                    # reply "ACK" once receive any message from sender

                    # segemnt has been skipped
                    if self.incoming_message[2:4] != self.expected_seq:
                        reply_seqno = int.from_bytes(self.last_seq_received, "big")
                    
                    # First segment has been skipped
                    elif len(self.seqs_received) == 0 and int.from_bytes(self.incoming_message[2:4], "big") == int.from_bytes(self.last_seq_received, "big") + 1:
                        reply_seqno = int.from_bytes(self.last_seq_received, "big")
                    else:
                        reply_seqno = int.from_bytes(self.incoming_message[2:4], "big") + data_length

                    # roll value around back to 0 if greater tha 2^16 - 1
                    if reply_seqno > 65535:
                        reply_seqno = (reply_seqno - (65535) - 1).to_bytes(2, "big")
                    else:
                        reply_seqno = reply_seqno.to_bytes(2, "big")

                    # send reply ack
                    typeACK = (1).to_bytes(2, byteorder='big', signed=False)
                    randval = random.uniform(0.0, 1.0)
                    reply_message = typeACK + reply_seqno
                    # check if dropping ack
                    if randval >= self.rlp:
                        send_ack(self, reply_message)
                        self.expected_seq = reply_seqno
                    else:
                        # write dropped ack in log
                        data = self.incoming_message[4:]
                        seq_num_int = int.from_bytes(reply_seqno, "big")
                        with open("Receiver_log.txt", "a+") as logfile:
                            if not self.connection_secured:
                                self.start_time = time.time()
                            logfile.write("drp".ljust(7) + str(round((time.time() - self.start_time), 2)).ljust(7) + "ACK".ljust(7) + str(seq_num_int).ljust(7) + str(0).ljust(7) + "\n")
                        logging.debug(f"drp\t\t{round((time.time() - self.start_time), 2)}\t\tACK\t\t{seq_num_int}\t\t{0}")
            else:
                # DATA has been dropped
                val = int.from_bytes(self.incoming_message[2:4], "big")
                data = self.incoming_message[4:]
                with open("Receiver_log.txt", "a+") as logfile:
                    if not self.connection_secured:
                        self.start_time = time.time()
                    logfile.write("drp".ljust(7) + str(round((time.time() - self.start_time), 2)).ljust(7) + "DATA".ljust(7) + str(val).ljust(7) + str(len(data)).ljust(7) + "\n")
                logging.debug(f"drp\t\t{round((time.time() - self.start_time), 2)}\t\DATA\t\t{val}\t\t{len(data)}")
                self.packet_lost = True
                #logging.debug(f"snd\t\tDATA\t{seq_num_int}\t\t{len(data)}")

def send_ack(self, reply_message):
    self.receiver_socket.sendto(reply_message,
                                self.sender_address)
    
    seq_num_int = int.from_bytes(reply_message[2:4], "big")
    data = reply_message[4:]
    with open("Receiver_log.txt", "a+") as logfile:
        logfile.write("snd".ljust(7) + str(round((time.time() - self.start_time), 2)).ljust(7) + "ACK".ljust(7) + str(seq_num_int).ljust(7) + str(len(data)).ljust(7) + "\n")
    logging.debug(f"snd\t\t{round((time.time() - self.start_time), 2)}\t\tACK\t\t{seq_num_int}\t\t{len(data)}")
    for message in self.buffer:
        if seq_num_int == int.from_bytes(self.incoming_message[2:4], "big"):
            break
        with open(self.filename, "ab+") as file:
            file.write(message[4:])
        with open("Receiver_log.txt", "a+") as logfile:
            logfile.write(f"just wrote to file from buffer\n")

        self.last_seq_received = message[2:4]
        self.buffer.remove(message)

def find_reply_seqno(self):
    reply_seqno = int.from_bytes(self.incoming_message[2:4], "big") + 1
    if reply_seqno > 65535:
        reply_seqno = (reply_seqno - (65535) - 1).to_bytes(2, "big")
    else:
        reply_seqno = reply_seqno.to_bytes(2, "big")
        return reply_seqno


if __name__ == '__main__':
    # logging is useful for the log part: https://docs.python.org/3/library/logging.html
    logging.basicConfig(
        # filename="Receiver_log.txt",
        stream=sys.stderr,
        level=logging.DEBUG,
        format='%(asctime)s,%(msecs)03d %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d:%H:%M:%S')

    if len(sys.argv) != 6:
        print(
            "\n===== Error usage, python3 receiver.py receiver_port sender_port FileReceived.txt flp rlp ======\n")
        exit(0)

    receiver = Receiver(*sys.argv[1:])
    receiver.run()

