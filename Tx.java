package Transmitter;

/* This package consists of the Tx and RC4 classes. Tx performs initial handshake by sending 
 INIT packet and receiving IACK. It then creates a random 351 bytes long payload and encrypts it 
 using RC4 algorithm. The data is divided into packets containing 40 bytes of payload data and 
 transmitted using stop and wait algorithm to the receiver*/

import java.util.*;
import java.net.*;
import java.io.*;

public class Tx {
	
	// Variable declarations
	private short integrity_check = 0;
	private short sequence_no;
	private short packet_type;
	static short LENGTH_OF_LAST_PACKET;
	static short initial_sequence_no;
	static short current_sequence_no;
	static byte[] nonce=new byte[8];
	static final int TIME_OUT_VALUE=1000;
	static final int PORT = 9999;
	static int MAX_NO_OF_PACKETS;
	
	public Tx(short integrity_check, short sequence_no, short packet_type) {
		this.integrity_check = integrity_check;
		this.sequence_no = sequence_no;
		this.packet_type = packet_type;
	}

	public Tx(short packet_type) {// Constructor overloading
		this.packet_type = packet_type;
	}

	public static void main(String[] args) throws Exception{
		
	// Performing initial handshake
	HandShake();
	
	byte[] payload = new byte[351];
	byte[] ciphertext = new byte[351];
	MAX_NO_OF_PACKETS=(351/40)+1;
	LENGTH_OF_LAST_PACKET=(short)351%40;
	
	// Generating random data for payload
	Random random = new Random();
	random.nextBytes(payload);
	
	// Displaying the data
	System.out.println("---------------------------------------------DATA------------------------------------------");
	displayPacket(payload);
		
	// Encrypting the data
	System.out.println("\nEncrypting DATA...");
	RC4 rc4 = new RC4(nonce);
	ciphertext=rc4.encrypt(payload);
	
	// Displaying the encrypted data
	System.out.println("---------------------------------------ENCRYPTED DATA--------------------------------------");
	displayPacket(ciphertext);
	System.out.println("\n-----------------------------------------------------------------------------------------");
	
	// Dividing the data into a 2D array 
	byte[][] data=new byte[MAX_NO_OF_PACKETS][40];
	int element=0,i,k;
	for(i=0;i<MAX_NO_OF_PACKETS-1;i++) {
		for(int j=0;j<40;j++){
			data[i][j]=ciphertext[element];
			element++;
		}
	}
	
	// Last packet
	for(k=0;k<(351%40);k++) {
		data[i][k]=ciphertext[element];
		element++;
	}
	
	// Zero padding for the last packet
	for(int l=k;l<40;l++) {
		data[i][k]=0;
	}
	
	// Transmitting the data to the receiver
	DataTransmission(data);
	}
	// End of main function
	
	public static void HandShake() throws Exception {

		InetAddress local_address = InetAddress.getByName("localhost");
		
		System.out.println("\n\n-------------INITIAL HANDSHAKE--------------");
		
		// Generating a random sequence number
		int sequence_no_MAX = 32767;
		Random random = new Random();
		short INIT_sequence_no = (short) ((random.nextInt(sequence_no_MAX)) & (0XFF));

		// Creating INIT object
		Tx INIT_obj = new Tx((short) 0, (short) INIT_sequence_no, (short) 0x00);
		int count = 0;
		boolean test = false;

		// Defining INIT packet in short
		short[] INIT_packet_short = new short[3];
		INIT_packet_short[0] = INIT_obj.packet_type;
		INIT_packet_short[1] = INIT_obj.sequence_no;
		INIT_packet_short[2] = INIT_obj.integrity_check;

		// Performing Integrity check
		INIT_obj.integrity_check = INIT_obj.integrityCheckCalculation(INIT_packet_short);
		INIT_packet_short[2] = INIT_obj.integrity_check;
		
		// Defining INIT packet in Bytes
		byte[] INIT_packet = new byte[6];
		INIT_packet = INIT_obj.convertShortByte(INIT_packet_short);

		// Sending the packet
		DatagramPacket INIT = new DatagramPacket(INIT_packet,INIT_packet.length, local_address, PORT);
		DatagramSocket transmitterSocket = new DatagramSocket();
		do {
			System.out.println("\nSending the INIT packet to the receiver...");
			transmitterSocket.send(INIT);
			count++;
			if (count > 4)
				break;

			// Receiving IACK from the receiver
			Tx IACK_obj = new Tx((short) 0x01);
			byte[] data_received = new byte[14];
			byte[] IACK_received = new byte[14];
			DatagramPacket packet_received = new DatagramPacket(data_received,data_received.length);
			transmitterSocket.setSoTimeout(TIME_OUT_VALUE*count);
			System.out.println("Receiving IACK from the receiver...");
			try {
				transmitterSocket.receive(packet_received);
			} 
			catch (SocketTimeoutException e) {
				System.out.println("Client socket timeout! Exception message: Receive timed out");
				System.exit(0);
			}
			IACK_received = packet_received.getData();
			
			// IACK byte contents
			System.out.println("\n----------------IACK contents-----------------");
			displayPacket(IACK_received);
			System.out.println("\n----------------------------------------------");

			// Retrieving nonce from IACK
			for(int i=5,j=0;i<13;i++,j++) {
				nonce[j]=IACK_received[i];
			}
			
			// Integrity check to determine correct reception of packet
			short INIT_sequence_no_echo_short;
			short[] IACK_received_short = new short[7];
			IACK_received_short = IACK_obj.convertByteShort(IACK_received);
			IACK_obj.integrity_check = IACK_received_short[6];
			IACK_obj.packet_type = IACK_received_short[0];
			IACK_obj.sequence_no = IACK_received_short[1];
			INIT_sequence_no_echo_short = IACK_obj.sequence_no;
			
			// Performing integrity check
			IACK_obj.integrity_check = IACK_obj.integrityCheckCalculation(IACK_received_short);
			
			// Checking if the packet arrived is correct
			if ((IACK_obj.integrity_check == 0) && (IACK_obj.packet_type == 1)&& (INIT_obj.sequence_no == INIT_sequence_no_echo_short))
				test = true;
			else
				test = false;
			initial_sequence_no=IACK_obj.sequence_no;
		} while (!test);
		System.out.println("\nHandshake successful!");
	}

	public static void DataTransmission(byte[][] data)throws Exception {

		System.out.println("\n\n------------------DATA TRANSMISSION-------------------");
		
		// Declarations
		MAX_NO_OF_PACKETS = data.length;
		int no_of_packets_sent = 0;
		short data_packet_type;
		short length;
		current_sequence_no = initial_sequence_no;
			
		InetAddress local_address = InetAddress.getByName("localhost");
		do {
			// Creating DATA object
			if(no_of_packets_sent<MAX_NO_OF_PACKETS-1){
				data_packet_type=0x02;
				length=(short)data[0].length;
			}
			else{
				data_packet_type=0x03;
				length=LENGTH_OF_LAST_PACKET;
			}
			Tx DATA_obj = new Tx((short)0, (short) current_sequence_no, data_packet_type);
			int count = 0;
			boolean test = false;

			// Defining DATA packet in short
			short[] DATA_packet_short = new short[24];
			short[] payload_short=new short[20];
			payload_short=DATA_obj.convertByteShort(data[no_of_packets_sent]);
			DATA_packet_short[0] = DATA_obj.packet_type;
			DATA_packet_short[1] = DATA_obj.sequence_no;
			DATA_packet_short[2] = length;
			for(int i=0,j=3;i<20;i++,j++){
				DATA_packet_short[j]=payload_short[i];
			}
			DATA_packet_short[23] = DATA_obj.integrity_check;
		
			// Integrity check
			DATA_obj.integrity_check = DATA_obj.integrityCheckCalculation(DATA_packet_short);
			DATA_packet_short[23] = DATA_obj.integrity_check;
			
			// Defining DATA packet in Bytes
			byte[] DATA_packet = new byte[48];
			DATA_packet = DATA_obj.convertShortByte(DATA_packet_short);
			short packet_type_received=(short)(DATA_packet[0]&(0xFF));
			packet_type_received=(short)((packet_type_received<<8)+(DATA_packet[1]&(0xFF)));
						
			// Sending the packet
			DatagramPacket DATA = new DatagramPacket(DATA_packet,DATA_packet.length, local_address, PORT);
			DatagramSocket transmitterSocket = new DatagramSocket();
			do{
				System.out.printf("\nSending DATA packet %d to the receiver...", (current_sequence_no-initial_sequence_no+1));
				//displayPacket(DATA_packet);
				transmitterSocket.send(DATA);
				count++;
				if (count > 4)
					break;
			
				// Receiving DACK from the receiver
				System.out.println("\nReceiving DACK...");
				Tx DACK_obj = new Tx((short) 0x04);
				byte[] data_received = new byte[6];
				byte[] DACK_received = new byte[6];
				DatagramPacket packet_received = new DatagramPacket(data_received, data_received.length);
				transmitterSocket.setSoTimeout(TIME_OUT_VALUE*count);
				try {
					transmitterSocket.receive(packet_received);
				} 
				catch (SocketTimeoutException e) {
					System.out.println("Client socket timeout! Exception message: Receive timed out");
					System.exit(0);
				}
				
				DACK_received = packet_received.getData();
			
				// DACK byte contents
				System.out.println("---------------DACK CONTENTS----------------");
				displayPacket(DACK_received);
			
				// Integrity check to determine correct reception of packet
				short[] DACK_received_short = new short[3];
				DACK_received_short = DACK_obj.convertByteShort(DACK_received);
				DACK_obj.integrity_check = DACK_received_short[2];
				DACK_obj.packet_type = DACK_received_short[0];
				DACK_obj.sequence_no = DACK_received_short[1];
			
				// Performing integrity check
				DACK_obj.integrity_check = DACK_obj.integrityCheckCalculation(DACK_received_short);
			
				// Checking if the DACK packet arrived is correct
				if ((DACK_obj.integrity_check == 0) && (DACK_obj.packet_type == 4)&& (DACK_obj.sequence_no == DATA_obj.sequence_no))
					test = true;
				else
					test = false;
				
			}while(!test);		 
				no_of_packets_sent++;
				current_sequence_no++;
				
				//Connection tear down
				if(DATA_obj.packet_type==3)
					transmitterSocket.close();
				
		} while (current_sequence_no < initial_sequence_no+MAX_NO_OF_PACKETS);
		System.out.println("\n-------------END OF DATA TRANSMISSION---------------");
	}

	// Function to perform integrity check calculation
	public short integrityCheckCalculation(short[] packet) {
		integrity_check = 0;
		if ((this.packet_type == 0x00)||(this.packet_type == 0x02)||(this.packet_type == 0x03)) {
			for (int i = 0; i < packet.length - 1; i++) {
				integrity_check = (short) (integrity_check ^ packet[i]);
			}
		} else if ((this.packet_type == 0x01) || (this.packet_type == 0x04)) {
			for (int i = 0; i < packet.length; i++) {
				integrity_check = (short) (integrity_check ^ packet[i]);
			}
		}
		return integrity_check;
	}

	// Function to convert byte array to short array
	public short[] convertByteShort(byte[] packet) {
		short[] packet_short = new short[packet.length / 2];
		for (int i = 0; i < packet_short.length; i++) {
			packet_short[i] = (short) (packet[i * 2] & (0xFF));
			packet_short[i] = (short) ((packet_short[i] << 8) + (packet[i * 2 + 1] & (0xFF)));
		}
		return packet_short;
	}

	// Function to convert short array to byte array
	public byte[] convertShortByte(short[] packet_short) {
		byte[] packet = new byte[packet_short.length * 2];
		for (int i = 0; i < packet_short.length; i++) {
			packet[i * 2 + 1] = (byte) (packet_short[i] & 0xFF);
			packet[i * 2] = (byte) ((packet_short[i] & 0xFF00) >> 8);
		}
		return packet;
	}

	// Function to display the contents of a byte array. It gives tab space between elements if the number
	// of elements in the array is greater than 20. Otherwise it prints each element in a new line
	public static void displayPacket(byte[] packet) {
		if(packet.length > 20){
			int count=0;
			for (int i=0; i < packet.length; i++){
				if (count % 15== 0)
					System.out.println();
				count++;
				System.out.printf("%d\t", packet[i]);
			}
		}
		else{
			for (int i = 0; i < packet.length; i++) {
				System.out.printf("Byte %d. = %d\n", i, packet[i]);
			}
		}
	}
}