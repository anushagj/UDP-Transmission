package Receiver;
/* Receiver package contains RX and RC4 classes. Rx class receives packets from transmitter and
sends IACK or DACK accordingly based on the packet type. The data received is then decrypted using
the same key as used for encryption using RC4 algorithm */

import java.util.*;
import java.net.*;
import java.io.*;

public class Rx {
	private short integrity_check = 0;
	private short sequence_no;
	private short packet_type;
	static short current_sequence_no;
	static short initial_sequence_no;
	static int PORT = 9999;
	static byte[] nonce=new byte[8];

	public Rx(short integrity_check, short sequence_no, short packet_type) {
		this.integrity_check = integrity_check;
		this.sequence_no = sequence_no;
		this.packet_type = packet_type;
	}

	public Rx(short packet_type) {
		this.packet_type = packet_type;
	}

	public static void main(String args[]) throws Exception{
	
		//Receiving a packet from the transmitter
		byte[] data_received = new byte[48];
		byte[] ciphertext=new byte[351];
		byte[] payload=new byte[360];
		byte[] payload_received_packet=new byte[40];
		int index=0,no_of_packets=0;
		DatagramPacket packet_received = new DatagramPacket(data_received,data_received.length);
		DatagramSocket socket = new DatagramSocket(PORT);
		while(true) {
			socket.receive(packet_received);
			InetAddress inetAddress = packet_received.getAddress();
			PORT = packet_received.getPort();
			byte[] data_retrieved = packet_received.getData();
			short packet_type_received,packet_length_received;
			packet_type_received=(short)(data_retrieved[0]&(0xFF));
			packet_type_received=(short)((packet_type_received<<8)+(data_retrieved[1]&(0xFF)));
			packet_length_received=(short)(data_retrieved[4]&(0xFF));
			packet_length_received=(short)((packet_length_received<<8)+(data_retrieved[5]&(0xFF)));
			if(packet_type_received==(short)0x00) {// Calling Handshake() function if packet type is 0
				HandShake(data_retrieved,inetAddress);
			}
			else if((packet_type_received==(short)0x02)||(packet_type_received==(short)0x03)){
				//  Calling DataTransmission() function if packet type is 2 or 3
				payload_received_packet=DataTransmission(data_retrieved,inetAddress);
				no_of_packets++;
				for(int i=0,j=index;i<packet_length_received;i++,j++){
					ciphertext[j]=payload_received_packet[i];
				}
			if(packet_type_received==(short)0x03)
					break;
				index=index+40;
			}
		}
		RC4 rc4 = new RC4(nonce);
		
		// Decrypting the DATA
		System.out.println("\nDecrypting the DATA received...");
		payload=rc4.decrypt(ciphertext);
		System.out.println("------------------------------------------------------------DECRYPTED DATA------------------------------------------------");
		displayPacket(payload);
		System.out.println("--------------------------------------------------------------------------------------------------------------------------");
	}
	
	public static void HandShake(byte[] data_retrieved, InetAddress inetAddress) throws Exception {

		System.out.println("\n\n-------------INITIAL HANDSHAKE--------------");
		System.out.println("\nReceiving INIT from transmitter...");
		
		// Receiving INIT packet
		byte[] INIT_received = new byte[6];
		for(int i=0;i<6;i++){
			INIT_received[i]=data_retrieved[i];
		}
		Rx INIT_obj=new Rx((short)0x00);
		
		// Display INIT contents
		System.out.println("---------------INIT CONTENTS--------------");
		displayPacket(INIT_received);

		// Converting INIT contents to short
		short[] INIT_received_short = new short[3];
		INIT_received_short=INIT_obj.convertByteShort(INIT_received);
		INIT_obj.sequence_no=INIT_received_short[1];
		
		// Performing integrity check
		INIT_obj.integrity_check=INIT_obj.integrityCheckCalculation(INIT_received_short);
		
		if((INIT_obj.integrity_check==0)&&(INIT_obj.packet_type==0)){
		
		// Generating random bytes for nonce
		Random random = new Random();
		random.nextBytes(nonce);
		
		// Defining IACK packet
		byte[] IACK_packet = new byte[14];
		short[] IACK_packet_short=new short[7];
		short INIT_sequence_no_echo_short = INIT_obj.sequence_no;
		Rx IACK_obj=new Rx((short)0,INIT_sequence_no_echo_short,(short)0x01);
		short[] nonce_short = new short[4];
		nonce_short=IACK_obj.convertByteShort(nonce);
		IACK_packet_short[0]=IACK_obj.packet_type;
		IACK_packet_short[1]=INIT_sequence_no_echo_short;
		for (int i = 0, j = 2; i<nonce_short.length; i++, j++) {
			IACK_packet_short[j] = nonce[i];
		}
		IACK_packet_short[6]=IACK_obj.integrity_check;
		initial_sequence_no=INIT_sequence_no_echo_short;
		current_sequence_no=initial_sequence_no;
				
		// Performing integrity check
		IACK_obj.integrity_check = IACK_obj.integrityCheckCalculation(IACK_packet_short);
		IACK_packet_short[6]=IACK_obj.integrity_check;
						
		// Converting IACK short to Byte
		IACK_packet=IACK_obj.convertShortByte(IACK_packet_short);
				
		// Sending IACK to transmitter
		DatagramPacket IACK = new DatagramPacket(IACK_packet,IACK_packet.length, inetAddress, PORT);
		System.out.println("Sending IACK...");
		DatagramSocket receiverSocket = new DatagramSocket();
		receiverSocket.send(IACK);
		}
	}
	
	public static byte[] DataTransmission(byte[] DATA_received, InetAddress inetAddress) throws Exception {
		
		// Declarations
		int count = 0;
		byte[] payload=new byte[40];
		
		// Retrieving packet type
		short packet_type;
		packet_type=(short)(DATA_received[0]&(0xFF));
		packet_type=(short)((packet_type<<8)+(DATA_received[1]&(0xFF)));
		
		Rx DATA_obj=new Rx(packet_type);
		System.out.printf("\nReceiving DATA packet %d from the transmitter...\n",current_sequence_no-initial_sequence_no+1);

		// Printing DATA contents
		System.out.println("-------------------------------------------------------DATA packet contents--------------------------------------------");
		displayPacket(DATA_received);

		// Converting DATA contents to short
		short[] DATA_received_short = new short[DATA_received.length/2];
		DATA_received_short=DATA_obj.convertByteShort(DATA_received);
		DATA_obj.sequence_no=DATA_received_short[1];
				
		// Performing integrity check
		DATA_obj.integrity_check=DATA_obj.integrityCheckCalculation(DATA_received_short);
		
		// Retrieving payload from DATA to return to main
		for(int i=0,j=6;i<DATA_received_short[2];i++,j++){
			payload[i]=DATA_received[j];
		}
		
		// Test condition
		boolean test=false;
		if((DATA_obj.integrity_check==0)&&((DATA_obj.packet_type==2)||(DATA_obj.packet_type==3))&&(DATA_obj.sequence_no==current_sequence_no))
			test=true;
		else
			test=false;
		if(test){
		
		// Defining DACK packet
		byte[] DACK_packet = new byte[6];
		short[] DACK_packet_short=new short[DACK_packet.length/2];
		short acknowledgement_no = DATA_obj.sequence_no;
		Rx DACK_obj=new Rx((short)0,acknowledgement_no,(short)0x04);
		DACK_packet_short[0]=DACK_obj.packet_type;
		DACK_packet_short[1]=DACK_obj.sequence_no;
		DACK_packet_short[2]=DACK_obj.integrity_check;
				
		// Performing integrity check
		DACK_obj.integrity_check = DACK_obj.integrityCheckCalculation(DACK_packet_short);
		DACK_packet_short[2]=DACK_obj.integrity_check;
						
		// Converting DACK short to Byte
		DACK_packet=DACK_obj.convertShortByte(DACK_packet_short);
				
		// Sending DACK to transmitter
		DatagramPacket DACK = new DatagramPacket(DACK_packet,DACK_packet.length, inetAddress, PORT);
		System.out.println("Sending DACK...");
		DatagramSocket receiverSocket = new DatagramSocket();
		receiverSocket.send(DACK);
		current_sequence_no++;
		}
		return payload;
	}
	
	// Function to perform integrity check calculation
	public short integrityCheckCalculation(short[] packet){
		integrity_check=0;
		if((this.packet_type==0x00)||(this.packet_type==0x02)||(this.packet_type==0x03)){
		for(int i=0;i<packet.length;i++){
			integrity_check=(short)(integrity_check^packet[i]);
			}
		}
		else if((this.packet_type==0x01)||(this.packet_type==0x04)){
			for(int i=0;i<packet.length-1;i++){
				integrity_check=(short)(integrity_check^packet[i]);
			}
		}
		return integrity_check;
	}

	// Function to convert byte array to short array
	public short[] convertByteShort(byte[] packet){
		short[] packet_short=new short[packet.length/2];
		for(int i=0;i<packet_short.length;i++){
			packet_short[i]=(short)(packet[i*2]&(0xFF));
			packet_short[i]=(short)((packet_short[i]<<8)+(packet[i*2+1]&(0xFF)));
		}
		return packet_short;
	}

	// Function to convert short array to byte array
	public byte[] convertShortByte(short[] packet_short){
		byte[] packet=new byte[packet_short.length*2];
		for(int i=0;i<packet_short.length;i++){
			packet[i*2+1]=(byte)(packet_short[i]&0xFF);
			packet[i*2]=(byte)((packet_short[i]&0xFF00)>>8);
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
				System.out.println();
			}
			else{
				for (int i = 0; i < packet.length; i++) {
					System.out.printf("Byte %d. = %d\n", i, packet[i]);
				}
			}
		}
}
